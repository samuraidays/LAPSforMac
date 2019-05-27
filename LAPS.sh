#!/bin/bash
####################################################################################################
#
#   MIT License
#
#   Copyright (c) 2016 University of Nebraska–Lincoln
#
#	Permission is hereby granted, free of charge, to any person obtaining a copy
#   of this software and associated documentation files (the "Software"), to deal
#   in the Software without restriction, including without limitation the rights
#   to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
#   copies of the Software, and to permit persons to whom the Software is
#   furnished to do so, subject to the following conditions:
#
#   The above copyright notice and this permission notice shall be included in all
#   copies or substantial portions of the Software.
#
#   THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
#   IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
#   FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
#   AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
#   LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
#   OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
#   SOFTWARE.
#
####################################################################################################

#-
#- Usage
#-  TBD
#-

if [ "$#" -eq 0 ]; then
    /usr/bin/grep ^#- "$0" | /usr/bin/cut -c 4-
    exit 0
fi

####################################################################################################
# FUNCTIONS
function scriptLogging(){
    # `scriptLogging "your message"` then logging file and put it std-out.
    # `scriptLogging "your message" 2` then logging file and put it std-err.
    # Other than 2 is ignored.
    local logfile scriptname timestamp label mode
    logfile="/Library/Logs/jamf-laps.$( /bin/data +%F).log"
    scriptname="$( /usr/bin/basename "$0" )"
    timestamp="$( /bin/date "+%F %T" )"
    mode="$2"
    case "${mode:-1}" in
        2 )
            label="[error]"
            echo "$timestamp $scriptname $label $1" | /usr/bin/tee -a "$logfile" >&2
            ;;
        * )
            label="[info]"
            echo "$timestamp $scriptname $label $1" | /usr/bin/tee -a "$logfile"
            ;;
    esac
}

function decryptString() {
    local string salt passphrase status errmsgfile errmsg
    string="$1"
    salt="$2"
    passphrase="$3"
    errmsgfile="$( /usr/bin/mktemp )"
    echo "$string" | /usr/bin/openssl enc -aes256 -d -a -A -S "$salt" -k "$passphrase" 2> "$errmsgfile"
    status="${PIPESTATUS[1]}"
    if [ "$status" -ne 0 ]; then
        errmsg="$( /bin/cat "$errmsgfile" )"
        scriptLogging "Decrypt failed: $errmsg" 2
    fi
    /bin/rm -f "$errmsgfile"
}

function retrievePassword(){
    local ua up udid attr response httpStatus
    ua="$1"
    up="$2"
    udid="$3"
    attr="$4"

    response="$( /usr/bin/curl -s -f -u "${ua}:${up}" -H "Accept: application/xml" \
                "${apiURL}/JSSResource/computers/udid/$udid/subset/extension_attributes" \
                -w "HTTPSTATUS:%{http_code}" )"

    httpStatus=$( echo "$response" | /usr/bin/tr -d '\n' | /usr/bin/sed -e 's/.*HTTPSTATUS://')
    if [ "$httpStatus" -ne 200 ];then
        scriptLogging "Cannot get stored password. JSS api call is failed with HTTP status is $httpStatus." 2
        exit 1
    fi

    echo "$response" | /usr/bin/sed -e 's/HTTPSTATUS\:.*//g' | \
        /usr/bin/xpath "//extension_attribute[name=\"$attr\"]/value/text()" 2>/dev/null
}

function uploadPassword(){
    local ua up udid attr pass xmlString tmpfile
    ua="$1"
    up="$2"
    udid="$3"
    attr="$4"
    pass="$5"

    tmpfile="$( /usr/bin/mktemp )"
    cat <<_XML > "$tmpfile"
<?xml version="1.0" encoding="UTF-8"?>
<computer>
    <extension_attributes>
        <extension_attribute>
            <name>${attr}</name>
            <value>${pass}</value>
        </extension_attribute>
    </extension_attributes>
</computer>
_XML
    xmlString="$( cat "$tmpfile" )"
    rm -f "$tmpfile"

    /usr/bin/curl -s -u "${ua}:${up}" -X PUT -H "Content-Type: text/xml" -d "$xmlString" \
                  "${apiURL}/JSSResource/computers/udid/${udid}"
    return $?
}

function changePassword(){
    local ua old new result
    ua="$1"
    old="$2"
    new="$3"
    /usr/sbin/sysadminctl -adminUser "$ua" -adminPassword "$old" -resetPasswordFor "$ua" -newPassword "$new"
    result=$?
    if [ "$result" -ne 0 ]; then
        scriptLogging "Failed to change password of $ua" 2
        exit 1
    fi

    /usr/bin/dscl /Local/Default -authonly "$ua" "$new" 2> /dev/null
    result=$?
    if [ "$result" -eq 0 ]; then
        scriptLogging "Password of $ua has changed in success."
    else
        scriptLogging "Given password of $ua is wrong. This is serious." 2
        exit 1
    fi
}

####################################################################################################
# REQUIRMENTS
jamfPlist=/Library/Preferences/com.jamfsoftware.jamf.plist
if [ -f "$jamfPlist" ]; then
    apiURL="$( /usr/libexec/PlistBuddy -c "print jss_url" "$jamfPlist" )"
fi
if [ -z "$apiURL" ]; then
    scriptLogging "Failed to get api URL from $jamfPlist" 2
    exit 1
fi

HWUUID="$( /usr/sbin/system_profiler SPHardwareDataType | /usr/bin/awk '/Hardware UUID:/ { print $3 }' )"

####################################################################################################
#- Jamf Parameters
#- - Parameter  4: API User Name
apiUser="$4"
if [ -z "$apiUser" ]; then
    scriptLogging "API User was not given via parameter 4" 2
    exit 1
fi

#- - Parameter  5: API User Password. It must be encrypted.
apiEncryptedPass="$5"
if [ -z "$apiEncryptedPass" ]; then
    scriptLogging "API User's passowrd was not given via parameter 5." 2
    exit 1
fi

#- - Parameter  6: Loacal Administrator User Name
laUserName="$6"
if [ -z "$laUserName" ]; then
    scriptLogging "LAPS user name was not given via parameter 6." 2
    exit 1
fi
msg="$( /usr/bin/dseditgroup -o checkmember -m "$laUserName" localaccounts 2>&1 )"
result=$?
if [ "$result" -ne 0 ]; then
    scriptLogging "${msg}. Return Code (dserr) is ${result}." 2
    exit 1
fi

#- - Parameter  7: Initial Encrypted Password of Loacal Administrator User
initialEncryptedPassForLadminUser="$7"
if [ -z "$initialEncryptedPassForLadminUser" ]; then
    scriptLogging "Initial Encrypted Password of LAPS User was not given via parameter 7." 2
    exit 1
fi

#- - Parameter  8: Extend Attribute Name.
extAttName="$8"
if [ -z "$extAttName" ]; then
    scriptLogging "Extend Attribute Name was not given via parameter 8." 2
    exit 1
fi

#- - Parameter  9: Salt & Passphrase for decrypt API user password.
#-                 format:: salt:passphrase
apiSaltPass="$9"
if [ -n "$apiSaltPass" ]; then
    saltAPI="$( echo "$apiSaltPass" | /usr/bin/tr -d "[:blank:]" | /usr/bin/awk -F: '{print $1}' )"
    passAPI="$( echo "$apiSaltPass" | /usr/bin/tr -d "[:blank:]" | /usr/bin/awk -F: '{print $2}' )"
else
    scriptLogging "Salt & Passphrase for decrypt API user password was not given via parameter 9" 2
    exit 1
fi
if [ -z "$saltAPI" ] || [ -z "$passAPI" ]; then
    scriptLogging "Invalit string format given via parameter 9" 2
    exit 1
fi

#- - Parameter 10: Salt & Passphrase for encrypt/decrypt Local Administrator User password.
#-                 format:: salt:passphrase
laSaltPass="${10}"
if [ -n "$laSaltPass" ]; then
    laSalt="$( echo "$laSaltPass" | /usr/bin/tr -d "[:blank:]" | /usr/bin/awk -F: '{print $1}' )"
    laPass="$( echo "$laSaltPass" | /usr/bin/tr -d "[:blank:]" | /usr/bin/awk -F: '{print $2}' )"
else
    scriptLogging "Salt & Passphrase for decrypt LAPS user password was not given via parameter 10" 2
    exit 1
fi
if [ -z "$laSalt" ] || [ -z "$laPass" ]; then
    scriptLogging "Invalit string format given via parameter 10" 2
    exit 1
fi

#- - Parameter 11: Salt & Passphrase for decrypt LAPS user's initial password.
#-                 format:: salt:passphrase
initialLaSaltPass="${11}"
if [ -n "$initialLaSaltPass" ]; then
    initLaSalt="$( echo "$initialLaSaltPass" | /usr/bin/tr -d "[:blank:]" | /usr/bin/awk -F: '{print $1}' )"
    initLaPass="$( echo "$initialLaSaltPass" | /usr/bin/tr -d "[:blank:]" | /usr/bin/awk -F: '{print $2}' )"
else
    scriptLogging "Salt & Passphrase for decrypt LAPS user's initial password was not given via parameter 11" 2
    exit 1
fi
if [ -z "$initLaSalt" ] || [ -z "$initLaPass" ]; then
    scriptLogging "Invalit string format given via parameter 11" 2
    exit 1
fi

####################################################################################################
# Decode API user Password
apiPass="$( decryptString "$apiEncryptedPass" "$saltAPI" "$passAPI" )"
if [ -z "$retrievedPassword" ]; then
    scriptLogging "Failed to decrypt API user's password" 2
    exit 1
fi

####################################################################################################
# Retrieve LAPS user password from Extent Attribute
previousEncryptedPassword="$( retrievePassword "$apiUser" "$apiPass" "$HWUUID" "$extAttName" )"
if [ -n "$previousEncryptedPassword" ]; then
    scriptLogging "Retrieved previous password is $previousEncryptedPassword  (encrypted)."
    retrievedPassword="$( decryptString "$previousEncryptedPassword" "$laSalt" "$laPass" )"
else
    scriptLogging "Could not get previous password. Try initial password for ${laUserName}."
    scriptLogging "Try to use initial password for ${laUserName}: $initialEncryptedPassForLadminUser (encrypted)."
    retrievedPassword="$( decryptString "$initialEncryptedPassForLadminUser" "$initLaSalt" "$initLaPass" )"
fi
if [ -z "$retrievedPassword" ]; then
    scriptLogging "Failed to decrypt previous password" 2
    exit 1
fi

####################################################################################################
# Check current password with Retrieved password
/usr/bin/dscl /Local/Default -authonly "$laUserName" "$retrievedPassword" 2> /dev/null
returnCode=$?
if [ "$returnCode" -eq 0 ]; then
    scriptLogging "Current password has match with Retrieved password."
else
    scriptLogging "Retrieved password for $laUserName is not match current password. dserr: $returnCode"  2
    exit $returnCode
fi

####################################################################################################
# Change password with new one.
newpassword="$( /usr/bin/openssl rand -base64 10 | /usr/bin/tr -d OoIi1lLS | /usr/bin/head -c 12 )"
changePassword "$laUserName" "$retrievedPassword" "$newpassword"

####################################################################################################
# Encrypt New Password
encryptedPassword="$( echo "$newpassword" | /usr/bin/openssl enc -aes256 -a -A -S "$laSalt" -k "$laPass" )"
if [ -n "$encryptedPassword" ]; then
    scriptLogging "New password: $encryptedPassword (Encrypted)"
else
    scriptLogging "Failed to encrypt new password. Why?" 2
    scriptLogging "Roll back with previous one."
    changePassword "$laUserName" "$newpassword" "$retrievedPassword"
    exit 1
fi

####################################################################################################
# Update Extent Attribute with New Password
uploadPassword "$apiUser" "$apiPass" "$HWUUID" "$extAttName" "$encryptedPassword"
returnCode=$?
if [ "$returnCode" -ne 0 ]; then
    scriptLogging "Failed to upload." 2
    scriptLogging "Roll back with previous one."
    changePassword "$laUserName" "$newpassword" "$retrievedPassword"
    exit 1
fi

try="$( retrievePassword "$apiUser" "$apiPass" "$HWUUID" "$extAttName" )"
if [ "$try" = "$encryptedPassword" ]; then
    scriptLogging "Retrieve test passed."
    status=0
else
    scriptLogging "Retrieve test failed. Get unexpected string." 2
    scriptLogging "Retrieved String: $try" 2
    scriptLogging "Expected String: $encryptedPassword" 2
    status=2
fi

scriptLogging "Done." "$status"
exit "$status"

#-
# vim: set ts=4 sw=4 sts=0 ft=sh fenc=utf-8 ff=unix :
