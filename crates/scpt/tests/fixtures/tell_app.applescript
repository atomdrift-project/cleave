-- Test script with tell application blocks
tell application "Finder"
    activate
    set desktopFolder to path to desktop
end tell

tell application "System Events"
    set processCount to count of processes
end tell

delay 1.0
