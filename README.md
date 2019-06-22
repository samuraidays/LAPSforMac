# LAPSforMac
Local Administrator Password Solution for Mac

## Purpose
macOS_LAPS.sh randomly changes the password of admin account of macOS computer and updates the inventory record of the macOS computer. You can securely manage the administrator password of the macOS computers being managed.

## Requirement
- macOS 10.14 or later.
- Every macOS computer has same initial password when it enrolled.

## Jamf Computer Extension Attribute

    Display Name: {extAttName}
    Description: This attribute will display the current Local Admin Password of the device.
    Data Type: String
    Inventory Display: General
    Input Type: Text Field
    Recon Display: User and Location (Not Used)

*Notes: The field is editable to allow for troubleshooting or manually overriding the password.*

## Jamf API User

    Username: {APIusername}
    Access Level: Full Access
    Privilege Set: Custom
    Access Status: Enabled
    Full Name: {APIusername}
    Email Address: (Not Used)
    Password: {APIpassword}
    Privileges:
    JSS Objects:
    Computer Extension Attributes: RU
    Computers: RU
    Users: U

*Notes: For Jamf permissions C=Create, R=Read, U=Update, D=Delete (Not sure why the "Users" permission is needed. After much trial and error, and a call to JAMF, I discovered this permission set was required to properly read and update the Computer tables)*

## Script parameters
    Parameter 4: API Username
    Parameter 5: API Password
    Parameter 6: LAPS Account Shortname
    Parameter 7:
    Parameter 8:
    Parameter 9:
    Parameter 10:
    Parameter 11:

## Log Location
You will find this script log as `/Library/Logs/Jamf_LAPS.YYYYMMDD.log`.

## Admintools
### DecryptString.sh
```
Usage:
 ./DecryptString.sh -e EncryptedString -p Passphrase -s Salt
 or
 ./path/to/DecryptString.sh -e EncryptedString -f Salt:Passphrase

-----
 eval $(path/to/EncryptString.sh plainTextString)
 decryptedString=$(path/to/DecryptString.sh -e $EncryptedString -p $Passphrase -s $Salt)
```
### EncryptString.sh
```
Usage:
 ./EncryptString.sh StringToEncrypt

 ------
 eval $( path/to/EncryptString.sh StringToEncrypt )
 echo "$EncryptedString $Salt $Passphrase $Saltphrase"
 ```
