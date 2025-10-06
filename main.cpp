#include <iostream>
#include <windows.h>
#include <vector>
#include <string>
#include <map>
#include <thread>
#include <mutex>
#include <TlHelp32.h>
#include <chrono>
#include <iomanip>

std::mutex consoleMutex;

struct TargetStatus 
{
    std::wstring name;
    std::string status = "Waiting...";
    int pidsFound = 0;
    bool cleaned = false;
};

void SetConsoleColor(WORD color) 
{
    SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), color);
}

void DrawInterface(const std::vector<TargetStatus>& statuses) 
{
    std::lock_guard<std::mutex> lock(consoleMutex);
    system("cls");

    for (const auto& status : statuses) {
        SetConsoleColor(FOREGROUND_GREEN | FOREGROUND_INTENSITY);
        std::wcout << L"[*] Target: " << status.name << std::endl;
        SetConsoleColor(FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
        std::cout << "    | PIDs Found: " << status.pidsFound << std::endl;
        std::cout << "    | Status: " << status.status << std::endl;

        if (status.cleaned) {
            SetConsoleColor(FOREGROUND_GREEN);
            std::cout << "    | [OK] Cleanup performed\n";
            SetConsoleColor(FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
        }

        std::cout << "    +-----------------------------------------------\n";
    }
    std::cout << "\nDetailed Logs:\n";
    std::cout << "-----------------------------------------------\n";
}

void Log(const std::string& message, const std::string& type = "INFO") 
{
    std::lock_guard<std::mutex> lock(consoleMutex);

    auto now = std::chrono::system_clock::now();
    auto time = std::chrono::system_clock::to_time_t(now);
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        now.time_since_epoch()) % 1000;

    struct tm timeinfo;
    localtime_s(&timeinfo, &time);

    std::cout << "[" << std::put_time(&timeinfo, "%H:%M:%S")
              << "." << std::setfill('0') << std::setw(3) << ms.count() << "] ";

    if (type == "INFO") {
        SetConsoleColor(FOREGROUND_BLUE | FOREGROUND_INTENSITY);
        std::cout << "[INFO] ";
    } else if (type == "SUCESS") {
        SetConsoleColor(FOREGROUND_GREEN | FOREGROUND_INTENSITY);
        std::cout << "[SUCESS] ";
    } else if (type == "ERRO") {
        SetConsoleColor(FOREGROUND_RED | FOREGROUND_INTENSITY);
        std::cout << "[ERRO] ";
    } else if (type == "AVISO") {
        SetConsoleColor(FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_INTENSITY);
        std::cout << "[AVISO] ";
    }

    std::cout << message << std::endl;
    SetConsoleColor(FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
}

BOOL EnablePrivilege() 
{
    HANDLE hToken;
    TOKEN_PRIVILEGES tkp;

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
        Log("Failed to open process token: " + std::to_string(GetLastError()), "ERRO");
        return FALSE;
    }

    if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &tkp.Privileges[0].Luid)) {
        Log("Failed to lookup SE_DEBUG_NAME privilege: " + std::to_string(GetLastError()), "ERRO");
        CloseHandle(hToken);
        return FALSE;
    }

    tkp.PrivilegeCount = 1;
    tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    if (!AdjustTokenPrivileges(hToken, FALSE, &tkp, 0, NULL, NULL)) {
        Log("Failed to adjust token privileges: " + std::to_string(GetLastError()), "ERRO");
        CloseHandle(hToken);
        return FALSE;
    }

    if (GetLastError() == ERROR_NOT_ALL_ASSIGNED) {
        Log("Could not assign all privileges", "ERRO");
        CloseHandle(hToken);
        return FALSE;
    }

    CloseHandle(hToken);
    Log("SE_DEBUG_NAME privilege enabled successfully", "SUCESS");
    return TRUE;
}

std::wstring StringToWideString(const std::string& str)
{
    if (str.empty()) {
        return L"";
    }

    int size = MultiByteToWideChar(CP_UTF8, 0, str.c_str(), -1, NULL, 0);

    if (size == 0) {
        Log("String conversion error: " + std::to_string(GetLastError()), "ERRO");
        return L"";
    }

    std::wstring wstr(size - 1, 0);
    MultiByteToWideChar(CP_UTF8, 0, str.c_str(), -1, &wstr[0], size);

    return wstr;
}

std::vector<DWORD> FindProcessIdsByName(const std::wstring& processName) 
{
    std::vector<DWORD> processIds;
    HANDLE hSnapshot;
    PROCESSENTRY32W pe32;

    hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

    if (hSnapshot == INVALID_HANDLE_VALUE) {
        Log("Failed to create process snapshot: " + std::to_string(GetLastError()), "ERRO");
        return {};
    }

    pe32.dwSize = sizeof(PROCESSENTRY32W);

    if (!Process32FirstW(hSnapshot, &pe32)) {
        Log("Failed to enumerate processes: " + std::to_string(GetLastError()), "ERRO");
        CloseHandle(hSnapshot);
        return {};
    }

    do {
        if (_wcsicmp(pe32.szExeFile, processName.c_str()) == 0) {
            processIds.push_back(pe32.th32ProcessID);
        }
    } while (Process32NextW(hSnapshot, &pe32));

    CloseHandle(hSnapshot);
    return processIds;
}

bool RemoveStringsFromProcess(DWORD processId, const std::vector<std::string>& sequences) 
{
    HANDLE hProcess = OpenProcess(PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_QUERY_INFORMATION,
                                  FALSE, processId);

    if (hProcess == NULL) {
        Log("Failed to open process PID " + std::to_string(processId) + ": " + std::to_string(GetLastError()), "AVISO");
        return false;
    }

    SYSTEM_INFO sysInfo;
    GetSystemInfo(&sysInfo);

    MEMORY_BASIC_INFORMATION memInfo;
    LPVOID address = sysInfo.lpMinimumApplicationAddress;
    LPVOID maxAddress = sysInfo.lpMaximumApplicationAddress;

    bool foundAndReplaced = false;
    int regionsScanned = 0;
    int matchesFound = 0;

    while (address < maxAddress) {
        if (VirtualQueryEx(hProcess, address, &memInfo, sizeof(memInfo)) == 0) {
            break;
        }

        if (memInfo.State == MEM_COMMIT &&
            (memInfo.Protect == PAGE_READWRITE ||
             memInfo.Protect == PAGE_EXECUTE_READWRITE ||
             memInfo.Protect == PAGE_WRITECOPY)) {

            regionsScanned++;
            std::vector<BYTE> buffer(memInfo.RegionSize);
            SIZE_T bytesRead;

            if (ReadProcessMemory(hProcess, memInfo.BaseAddress, buffer.data(), memInfo.RegionSize, &bytesRead)) {
                for (const auto& sequence : sequences) {
                    size_t seqLen = sequence.length();

                    for (SIZE_T i = 0; i <= bytesRead - seqLen; i++) {
                        if (memcmp(buffer.data() + i, sequence.c_str(), seqLen) == 0) {
                            std::vector<BYTE> zeros(seqLen, 0);
                            SIZE_T bytesWritten;

                            DWORD oldProtect;
                            VirtualProtectEx(hProcess, (LPVOID)((BYTE*)memInfo.BaseAddress + i),
                                             seqLen, PAGE_READWRITE, &oldProtect);

                            if (WriteProcessMemory(hProcess, (LPVOID)((BYTE*)memInfo.BaseAddress + i),
                                                   zeros.data(), zeros.size(), &bytesWritten)) {
                                matchesFound++;
                                foundAndReplaced = true;

                                std::stringstream ss;
                                ss << "String '" << sequence << "' removed at address 0x"
                                   << std::hex << ((BYTE*)memInfo.BaseAddress + i)
                                   << " (PID: " << std::dec << processId << ")";
                                Log(ss.str(), "SUCESS");
                            }

                            VirtualProtectEx(hProcess, (LPVOID)((BYTE*)memInfo.BaseAddress + i),
                                             seqLen, oldProtect, &oldProtect);
                        }
                    }
                }
            }
        }

        address = (LPVOID)((BYTE*)memInfo.BaseAddress + memInfo.RegionSize);
    }

    CloseHandle(hProcess);

    std::stringstream ss;
    ss << "PID " << processId << ": " << regionsScanned << " regions scanned, "
       << matchesFound << " strings removed";
    Log(ss.str(), foundAndReplaced ? "INFO" : "AVISO");

    return foundAndReplaced;
}

DWORD GetProcessIdByServiceName(const std::wstring& serviceName) 
{
    SC_HANDLE scManager = OpenSCManager(NULL, NULL, SC_MANAGER_CONNECT);
    if (!scManager) {
        return 0;
    }

    SC_HANDLE scService = OpenService(scManager, serviceName.c_str(), SERVICE_QUERY_STATUS);
    if (!scService) {
        CloseServiceHandle(scManager);
        return 0;
    }

    SERVICE_STATUS_PROCESS ssp;
    DWORD bytesNeeded;
    if (!QueryServiceStatusEx(scService, SC_STATUS_PROCESS_INFO, (LPBYTE)&ssp, sizeof(ssp), &bytesNeeded)) {
        CloseServiceHandle(scService);
        CloseServiceHandle(scManager);
        return 0;
    }

    CloseServiceHandle(scService);
    CloseServiceHandle(scManager);

    return ssp.dwProcessId;
}

bool TerminateProcessById(DWORD processId) {
    HANDLE hProcess = OpenProcess(PROCESS_TERMINATE, FALSE, processId);
    if (hProcess == NULL) {
        return false;
    }

    bool success = TerminateProcess(hProcess, 1);
    CloseHandle(hProcess);
    return success;
}

void CleanTargetWorker(
    TargetStatus* targetStatus,
    const std::vector<std::wstring>& processNames,
    const std::vector<std::wstring>& serviceNames,
    const std::vector<std::string>& stringsToRemove)
{
    targetStatus->status = "Searching PIDs...";

    std::vector<DWORD> pids;

    for (const auto& name : processNames) {
        auto found = FindProcessIdsByName(name);
        if (!found.empty()) {
            std::wstring nameW = name;
            std::string nameA(nameW.begin(), nameW.end());
            Log("Found " + std::to_string(found.size()) + " process(es) '" + nameA + "'", "INFO");
        }
        pids.insert(pids.end(), found.begin(), found.end());
    }

    for (const auto& name : serviceNames) {
        DWORD pid = GetProcessIdByServiceName(name);
        if (pid != 0) {
            std::wstring nameW = name;
            std::string nameA(nameW.begin(), nameW.end());
            Log("Service '" + nameA + "' found (PID: " + std::to_string(pid) + ")", "INFO");
            pids.push_back(pid);
        }
    }

    targetStatus->pidsFound = pids.size();

    if (pids.empty()) {
        targetStatus->status = "No process found.";
        Log("No process/service found for target '" +
            std::string(targetStatus->name.begin(), targetStatus->name.end()) + "'", "AVISO");
        return;
    }

    targetStatus->status = "Cleaning memory...";
    bool anyCleaned = false;

    for (DWORD pid : pids) {
        if (RemoveStringsFromProcess(pid, stringsToRemove)) {
            anyCleaned = true;
        }
    }

    targetStatus->cleaned = anyCleaned;
    targetStatus->status = anyCleaned ? "Cleanup complete!" : "No string found.";
}

int main()
{
    SetConsoleTitle(TEXT("Trace Cleaner v3.0 (Multithread)"));
    SetConsoleOutputCP(CP_UTF8);

    if (!EnablePrivilege()) {
        Log("Failed to obtain privileges. Run as administrator.", "ERRO");
        system("pause");
        return 1;
    }

    Log("Program started successfully", "INFO");

    std::vector<TargetStatus> statuses = {
        { L"Explorer", "Waiting..." },
        { L"Diagnostic Services", "Waiting..." },
        { L"Other Processes", "Waiting..." }
    };

    DrawInterface(statuses);

    std::vector<std::thread> threads;

    Log("Starting cleanup threads...", "INFO");

    threads.emplace_back(CleanTargetWorker,
        &statuses[0],
        std::vector<std::wstring>{ L"explorer.exe" },
        std::vector<std::wstring>{},
        std::vector<std::string>{ "131.196.198.50", "vps-32704700.vps.ovh.ca", "skript.gg" }
    );

    threads.emplace_back(CleanTargetWorker,
        &statuses[1],
        std::vector<std::wstring>{},
        std::vector<std::wstring>{ L"PcaSvc", L"Dps" },
        std::vector<std::string>{ "gosth.gg", "114.0.1823.67" }
    );

    threads.emplace_back(CleanTargetWorker,
        &statuses[2],
        std::vector<std::wstring>{ L"discord.exe", L"opera.exe" },
        std::vector<std::wstring>{},
        std::vector<std::string>{ "!!taskkill.exe" }
    );

    bool all_done = false;
    while (!all_done) {
        DrawInterface(statuses);
        all_done = true;
        for (const auto& s : statuses) {
            if (s.status.find("...") != std::string::npos) {
                all_done = false;
                break;
            }
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(150));
    }

    for (auto& t : threads) {
        if (t.joinable()) {
            t.join();
        }
    }

    DrawInterface(statuses);
    Log("Memory cleanup phase finished.", "SUCESS");

    Log("Starting process termination and service restart...", "INFO");

    std::vector<DWORD> pidsToKill = FindProcessIdsByName(L"SearchIndexer.exe");
    for (DWORD pid : pidsToKill) {
        if (TerminateProcessById(pid)) {
            Log("Process SearchIndexer.exe (PID: " + std::to_string(pid) + ") terminated.", "SUCESS");
        } else {
            Log("Failed to terminate SearchIndexer.exe (PID: " + std::to_string(pid) + ")", "ERRO");
        }
    }

    Log("Restarting Explorer...", "INFO");
    system("taskkill /f /im explorer.exe > nul 2>&1");
    std::this_thread::sleep_for(std::chrono::milliseconds(500));
    system("start explorer.exe");
    Log("Explorer.exe restarted.", "SUCESS");

    std::cout << "\n";
    Log("All operations completed successfully.", "SUCESS");
    system("pause");

    return 0;
}
