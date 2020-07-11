#!/bin/bash
## postinstall

mainDaemonPlist="/Library/LaunchDaemons/lapsForMac.plist"
mainScript="/Library/Scripts/call-jamf-policy-laps.sh"
identifier="lapsForMac"

# Set permissions on LaunchDaemon and Script
chown root:wheel "$mainDaemonPlist"
chmod 644 "$mainDaemonPlist"

chown root:wheel "$mainScript"
chmod 755 "$mainScript"

# Load our LaunchDaemons
/bin/launchctl load -w "$mainDaemonPlist"

# Start the main LaunchDaemon
/bin/launchctl start "$identifier"

exit 0		## Success
