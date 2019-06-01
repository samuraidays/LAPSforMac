#!/bin/bash
# vim: set ts=4 sw=4 sts=0 ft=sh fenc=utf-8 ff=unix :

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
#-   TBD
#-
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
    logfile="/Library/Logs/LapsAccountCreation.log"
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

#- - Parameter  6: Salt & Passphrase for decrypt API user password.
#-                 format:: salt:passphrase
apiSaltPass="$6"
if [ -n "$apiSaltPass" ]; then
    saltAPI="$( echo "$apiSaltPass" | /usr/bin/tr -d "[:blank:]" | /usr/bin/awk -F: '{print $1}' )"
    passAPI="$( echo "$apiSaltPass" | /usr/bin/tr -d "[:blank:]" | /usr/bin/awk -F: '{print $2}' )"
else
    scriptLogging "Salt & Passphrase for decrypt API user password was not given via parameter 6" 2
    exit 1
fi
if [ -z "$saltAPI" ] || [ -z "$passAPI" ]; then
    scriptLogging "Invalit string format given via parameter 6" 2
    exit 1
fi

#- - Parameter  7: Extend Attribute Name.
extAttName="$8"
if [ -z "$extAttName" ]; then
    scriptLogging "Extend Attribute Name was not given via parameter 7." 2
    exit 1
fi






# HARDCODED VALUES SET HERE
apiPass="$( decryptString "$apiEncryptedPass" "$saltAPI" "$passAPI" )"
LAPSuser=""
LAPSuserDisplay=""
newPass=""
LAPSaccountEvent=""
LAPSaccountEventFVE=""
LAPSrunEvent=""


# CHECK TO SEE IF A VALUE WAS PASSED IN PARAMETER 6 AND, IF SO, ASSIGN TO "LAPSuser"
if [ "$6" != "" ] && [ "$LAPSuser" == "" ];then
LAPSuser=$6
fi

# CHECK TO SEE IF A VALUE WAS PASSED IN PARAMETER 7 AND, IF SO, ASSIGN TO "LAPSuserDisplay"
if [ "$7" != "" ] && [ "$LAPSuserDisplay" == "" ];then
LAPSuserDisplay=$7
fi

# CHECK TO SEE IF A VALUE WAS PASSED IN PARAMETER 8 AND, IF SO, ASSIGN TO "newPass"
if [ "$8" != "" ] && [ "$newPass" == "" ];then
newPass=$8
fi

# CHECK TO SEE IF A VALUE WAS PASSED IN PARAMETER 9 AND, IF SO, ASSIGN TO "LAPSaccountEvent"
if [ "$9" != "" ] && [ "$LAPSaccountEvent" == "" ];then
LAPSaccountEvent=$9
fi

# CHECK TO SEE IF A VALUE WAS PASSED IN PARAMETER 10 AND, IF SO, ASSIGN TO "LAPSaccountEventFVE"
if [ "${10}" != "" ] && [ "$LAPSaccountEventFVE" == "" ];then
LAPSaccountEventFVE="${10}"
fi

# CHECK TO SEE IF A VALUE WAS PASSED IN PARAMETER 11 AND, IF SO, ASSIGN TO "LAPSrunEvent"
if [ "${11}" != "" ] && [ "$LAPSrunEvent" == "" ];then
LAPSrunEvent="${11}"
fi

xmlString="<?xml version=\"1.0\" encoding=\"UTF-8\"?><computer><extension_attributes><extension_attribute><name>LAPS</name><value>$newPass</value></extension_attribute></extension_attributes></computer>"

FVEstatus=$(fdesetup status | grep -w "FileVault is" | awk '{print $3}' | sed 's/[.]//g')


scriptLogging "======== Starting LAPS Account Creation ========"
scriptLogging "Checking parameters."

# Verify parameters are present
if [ "$apiUser" == "" ];then
    scriptLogging "The parameter 'API Username' is blank.  Please specify a user." 2
    scriptLogging "======== Aborting LAPS Account Creation ========" 2
    exit 1
fi

if [ "$apiPass" == "" ];then
    scriptLogging "The parameter 'API Password' is blank.  Please specify a password." 2
    scriptLogging "======== Aborting LAPS Account Creation ========" 2
    exit 1
fi

if [ "$LAPSuser" == "" ];then
    scriptLogging "The parameter 'LAPS Account Shortname' is blank.  Please specify a user to create." 2
    scriptLogging "======== Aborting LAPS Account Creation ========" 2
    exit 1
fi

if [ "$LAPSuserDisplay" == "" ];then
    scriptLogging "The parameter 'LAPS Account Displayname' is blank.  Please specify a user to create." 2
    scriptLogging "======== Aborting LAPS Account Creation ========" 2
    exit 1
fi

if [ "$newPass" == "" ];then
    scriptLogging "The parameter 'LAPS Password Seed' is blank.  Please specify a password to seed." 2
    scriptLogging "======== Aborting LAPS Account Creation ========" 2
    exit 1
fi

if [ "$LAPSaccountEvent" == "" ];then
    scriptLogging "The parameter 'LAPS Account Event' is blank.  Please specify a Custom LAPS Account Event." 2
    scriptLogging "======== Aborting LAPS Account Creation ========" 2
    exit 1
fi

if [ "$LAPSaccountEventFVE" == "" ];then
    scriptLogging "The parameter 'LAPS Account Event FVE' is blank.  Please specify a Custom LAPS Account Event." 2
    scriptLogging "======== Aborting LAPS Account Creation ========" 2
    exit 1
fi

if [ "$LAPSrunEvent" == "" ];then
    scriptLogging "The parameter 'LAPS Run Event' is blank.  Please specify a Custom LAPS Run Event." 2
    scriptLogging "======== Aborting LAPS Account Creation ========" 2
    exit 1
fi

# Verify resetUser is not a local user on the computer
checkUser="$( dseditgroup -o checkmember -m "$LAPSuser" localaccounts | awk '{ print $1 }' )"

if [[ "$checkUser" = "yes" ]];then
    scriptLogging "$LAPSuser already exists as a local user on the Computer" 2
    scriptLogging "======== Aborting LAPS Account Creation ========" 2
    exit 1
else
    scriptLogging "$LAPSuser is not a local user on the Computer, proceeding..."
fi

scriptLogging "Parameters Verified."


# Create the User Account
CreateLAPSaccount (){
    scriptLogging "Creating LAPS Account..."
    if [ "$FVEstatus" == "Off" ];then
        /usr/local/bin/jamf policy -event "$LAPSaccountEvent"
        scriptLogging "LAPS Account Created..."
    else
        /usr/local/bin/jamf policy -event "$LAPSaccountEventFVE"
        scriptLogging "LAPS Account Created with FVE..."
    fi
}

# Update the LAPS Extention Attribute
UpdateAPI (){
    scriptLogging "Recording new password for $LAPSuser into LAPS."
    /usr/bin/curl -s -f -u "${apiUser}:${apiPass}" -X PUT -H "Content-Type: text/xml" -d "${xmlString}" "${apiURL}/JSSResource/computers/udid/${HWUUID}"
}

# Check to see if the account is authorized with FileVault 2
FVEcheck (){
    userCheck="$( fdesetup list | awk -v usrN="$LAPSuserDisplay" -F, 'index($0, usrN) {print $1}' )"
        if [ "${userCheck}" == "${LAPSuserDisplay}" ]; then
            scriptLogging "$LAPSuserDisplay is enabled for FileVault 2." 2
        else
            scriptLogging "$LAPSuserDisplay is not enabled for FileVault 2." 2
        fi
}

# If FileVault Encryption is enabled, verify account.
FVEverify (){
    scriptLogging "Checking FileVault Status..."
    if [ "$FVEstatus" == "On" ];then
        scriptLogging "FileVault is enabled, checking $LAPSuserDisplay..."
        FVEcheck
    else
        scriptLogging "FileVault is not enabled."
    fi
}

UpdateAPI
CreateLAPSaccount
UpdateAPI
FVEverify

scriptLogging "======== LAPS Account Creation Complete ========"

# Run LAPS Password Randomization
/usr/local/bin/jamf policy -event "$LAPSrunEvent"

exit 0
