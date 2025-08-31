#include <iostream>
#include <windows.h>
#include <TlHelp32.h>
#include <wchar.h>


static DWORD getPID(const wchar_t* processName)
{
    PROCESSENTRY32* Entry32 = new PROCESSENTRY32();
    // According to the info on the Macrosoft website, you need to write the size of PROCESSENTRY32 in dwSize, otherwise nothing will work.
    Entry32->dwSize = sizeof(PROCESSENTRY32);
    // Snapshot of all processes in the system
    HANDLE pslist = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
    DWORD pId;
    if (pslist == INVALID_HANDLE_VALUE)
    {
        std::cout << "[-] Fail in getting list of processes";
        return 0;
    }
    else
        // we go through the list in the snapshot and look for the one we need
        while (Process32Next(pslist, Entry32))
        {
            if (wcscmp(processName, Entry32->szExeFile) == 0)
            {
                std::cout << "[+] Process found" << "\n";
                pId = Entry32->th32ProcessID;
                std::wcout << L"Process name: " << Entry32->szExeFile << L", PID " << pId << "\n";
                return pId;
            }
        }
    std::cout << "[-] Process not found" << "\n";
    CloseHandle(pslist);
    delete(Entry32);
    return 0;
}

static DWORD64 getBase(const wchar_t* module, DWORD pId)
{
    MODULEENTRY32* Module32 = new MODULEENTRY32();
    Module32->dwSize = sizeof(MODULEENTRY32);
    HANDLE mods = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pId);
    DWORD64 baseAddr;
    if (mods == INVALID_HANDLE_VALUE)
    {
        std::cout << "[-] Fail in getting list of process modules\n";
        return 0;
    }
    std::cout << "[+] Getting list of process modules...\n";
    if (Module32First(mods, Module32))
    {
        do {
            if (wcscmp(module, Module32->szModule) == 0)
            {
                std::wcout << L"[+] Module " << Module32->szModule << L" found!\n";
                baseAddr = (DWORD64)(Module32->modBaseAddr);
                CloseHandle(mods);
                delete(Module32);
                return baseAddr;
            }
            std::wcout << Module32->szModule << "\n";
        } while (Module32Next(mods, Module32));
    }
    std::cout << "[-] Module not found.\n";
    std::cout << "[-] Fail reading process modules\n";
    CloseHandle(mods);
    delete(Module32);
    return 0;
}

namespace driver {
    //control codes for driver
    namespace codes {
        //to setup a driver
        constexpr ULONG attach = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x696, METHOD_BUFFERED, FILE_SPECIAL_ACCESS);
        //Read process memory
        constexpr ULONG read = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x697, METHOD_BUFFERED, FILE_SPECIAL_ACCESS);
        //Write Process memory
        constexpr ULONG write = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x698, METHOD_BUFFERED, FILE_SPECIAL_ACCESS);
    }
    //for communication with UM
    struct Request {
        HANDLE process_id;
        PVOID target;
        PVOID buffer;
        SIZE_T size;
        SIZE_T return_size;
    };

    bool attach_to_process(HANDLE driver_handle, const DWORD pid)
    {
        Request r;
        r.process_id = (HANDLE)(pid);
        return DeviceIoControl(driver_handle, codes::attach, &r, sizeof(r), &r, sizeof(r), nullptr, nullptr);
    }

    template <typename T>
    T readMemory(HANDLE driver_handle, DWORD64 addr)
    {
        T temp = {};
        Request r;
        r.target = (PVOID)(addr);
        r.buffer = &temp;
        r.size = sizeof(T);
        DeviceIoControl(driver_handle, codes::read, &r, sizeof(r), &r, sizeof(r), nullptr, nullptr);
        return temp;
    }
    
    template <typename T>
    void writeMemory(HANDLE driver_handle, DWORD64 addr, const T &value)
    {
        Request r;
        r.target = (PVOID)(addr);
        r.buffer = (PVOID)&value;
        r.size = sizeof(T);
        DeviceIoControl(driver_handle, codes::write, &r, sizeof(r), &r, sizeof(r), nullptr, nullptr);
    }
}

int main()
{
    //notepad.exe
    const DWORD pid = getPID(L"notepad.exe");
    if (pid == 0)
    {
        std::cin.get();
        return 1;
    }

    const HANDLE driver = CreateFile(L"\\\\.\\FirstDriver", GENERIC_READ, 0, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (driver == INVALID_HANDLE_VALUE)
    {
        std::cout << "[-] Failed to create handle for the driver.\n";
        std::cin.get();
        return 1;
    }

    if (driver::attach_to_process(driver, pid) == true)
    {
        std::cout << "[+] Attachment success!\n";
    }

    CloseHandle(driver);
    DWORD64 base = getBase(L"notepad.exe", getPID(L"notepad.exe"));
    std::cout << "[+] Base address is: 0x" << std::hex << base << "\n";
    std::cin.get();
	return 1;
}