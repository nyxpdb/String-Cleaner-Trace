#include <iostream>
#include <windows.h>
#include <vector>
#include <string>
#include <map>
#include <thread>
#include <mutex>
#include <TlHelp32.h>
#include <chrono> 

std::mutex consoleMutex;

struct TargetStatus {
    std::wstring name;
    std::string status = "Aguardando...";
    int pidsFound = 0;
    bool cleaned = false;
};

void SetConsoleColor(WORD color) {
    SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), color);
}

void DrawInterface(const std::vector<TargetStatus>& statuses) {
    std::lock_guard<std::mutex> lock(consoleMutex);
    system("cls");
    SetConsoleColor(FOREGROUND_BLUE | FOREGROUND_INTENSITY);
    std::cout << "[INFO] Atualizando interface...\n";
    SetConsoleColor(FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
    
    for (const auto& status : statuses) {
        SetConsoleColor(FOREGROUND_GREEN);
        std::wcout << L"[*] Alvo: " << status.name << std::endl;
        SetConsoleColor(FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
        std::cout << "    | PIDs Encontrados: " << status.pidsFound << std::endl;
        std::cout << "    | Status: " << status.status << std::endl;
        std::cout << "    +-----------------------------------------------\n";
    }
    std::cout << "\nLogs Detalhados:\n";
}

void Log(const std::string& message, const std::string& type = "INFO") {
    std::lock_guard<std::mutex> lock(consoleMutex);
    if (type == "INFO") {
        SetConsoleColor(FOREGROUND_BLUE | FOREGROUND_INTENSITY);
        std::cout << "[INFO] " << message << std::endl;
    } else if (type == "SUCESS") {
        SetConsoleColor(FOREGROUND_GREEN | FOREGROUND_INTENSITY);
        std::cout << "[SUCESS] " << message << std::endl;
    } else if (type == "ERRO") {
        SetConsoleColor(FOREGROUND_RED | FOREGROUND_INTENSITY);
        std::cout << "[ERRO] " << message << std::endl;
    } else if (type == "AVISO") {
        SetConsoleColor(FOREGROUND_YELLOW | FOREGROUND_INTENSITY);
        std::cout << "[AVISO] " << message << std::endl;
    }
    SetConsoleColor(FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
}

BOOL EnablePrivilege() { 
    /* Código anterior mantido */ 
    return TRUE; 
}

std::wstring StringToWideString(const std::string& str) { 
    /* Código anterior mantido */
    return L""; 
}

std::vector<DWORD> FindProcessIdsByName(const std::wstring& processName) { 
    /* Código anterior mantido */
    return {}; 
}

bool RemoveStringsFromProcess(DWORD processId, const std::vector<std::string>& sequences) { 
    /* Código anterior mantido */
    return false; 
}

DWORD GetProcessIdByServiceName(const std::wstring& serviceName) {
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
    targetStatus->status = "Procurando PIDs...";
    
    std::vector<DWORD> pids;
    for (const auto& name : processNames) {
        auto found = FindProcessIdsByName(name);
        pids.insert(pids.end(), found.begin(), found.end());
    }
    for (const auto& name : serviceNames) {
        DWORD pid = GetProcessIdByServiceName(name);
        if (pid != 0) {
            pids.push_back(pid);
        }
    }
    
    targetStatus->pidsFound = pids.size();

    if (pids.empty()) {
        targetStatus->status = "Nenhum processo encontrado.";
        return;
    }

    targetStatus->status = "Limpando memoria...";
    bool anyCleaned = false;
    for (DWORD pid : pids) {
        if (RemoveStringsFromProcess(pid, stringsToRemove)) {
            anyCleaned = true;
        }
    }

    targetStatus->cleaned = anyCleaned;
    targetStatus->status = anyCleaned ? "Limpeza concluida!" : "Nenhuma string encontrada.";
}

int main() 
{
    SetConsoleTitle(TEXT("Limpador de Traces v3.0 (Multithread)"));
    if (!EnablePrivilege()) {
        Log("Falha ao obter privilegios. Execute como administrador.", "ERRO");
        system("pause");
        return 1;
    }

    Log("Iniciando programa...", "INFO");

    std::vector<TargetStatus> statuses = {
        { L"Explorer", "Aguardando..." },
        { L"Servicos de Diagnostico", "Aguardando..." },
        { L"Outros Processos", "Aguardando..." }
    };
    
    DrawInterface(statuses);

    std::vector<std::thread> threads;

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
        std::this_thread::sleep_for(std::chrono::milliseconds(100)); 
    }
    
    for (auto& t : threads) {
        if (t.joinable()) {
            t.join();
        }
    }

    DrawInterface(statuses);
    Log("Fase de limpeza de memoria finalizada.", "SUCESS");

    Log("Iniciando finalizacao de processos e reinicio de servicos...", "INFO");
    std::vector<DWORD> pidsToKill = FindProcessIdsByName(L"SearchIndexer.exe");
    for (DWORD pid : pidsToKill) {
        if (TerminateProcessById(pid)) {
            Log("Processo SearchIndexer.exe (PID: " + std::to_string(pid) + ") finalizado.", "SUCESS");
        }
    }
    
    system("taskkill /f /im explorer.exe > nul");
    system("start explorer.exe");
    Log("Explorer.exe reiniciado.", "SUCESS");

    Log("Operacao concluida.", "SUCESS");
    system("pause");

    return 0;
}
