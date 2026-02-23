-- Test script with shell script command
set userName to do shell script "whoami"
set hostName to do shell script "hostname"
set currentDir to do shell script "pwd"

delay 0.5

do shell script "echo " & quoted form of userName & " > /tmp/user.txt"
