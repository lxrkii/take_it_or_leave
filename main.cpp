#include <iostream>
#include <iomanip>
#include <cstdint>
#include <cstring>
#include <vector>
#include <string>
#include <sstream>
#include <fstream>
#include <unistd.h>
#include <sys/mman.h>

// Определения типов и констант Win32 API
using DWORD = uint32_t;
using WORD = uint16_t;
using SIZE_T = size_t;
using LPVOID = void*;
using LPCVOID = const void*;
using BOOL = int;

// state
#define MEM_COMMIT  0x00001000
#define MEM_RESERVE 0x00002000
#define MEM_FREE    0x00010000

// type
#define MEM_PRIVATE 0x00020000
#define MEM_MAPPED  0x00040000
#define MEM_IMAGE   0x01000000

// protect
#define PAGE_NOACCESS          0x01
#define PAGE_READONLY          0x02
#define PAGE_READWRITE         0x04
#define PAGE_WRITECOPY         0x08
#define PAGE_EXECUTE           0x10
#define PAGE_EXECUTE_READ      0x20
#define PAGE_EXECUTE_READWRITE 0x40
#define PAGE_GUARD             0x100

// system_info struct.
struct SYSTEM_INFO {
    WORD wProcessorArchitecture;
    WORD wReserved;
    DWORD dwPageSize;
    LPVOID lpMinimumApplicationAddress;
    LPVOID lpMaximumApplicationAddress;
     uintptr_t dwActiveProcessorMask;
    DWORD dwNumberOfProcessors;
    DWORD dwProcessorType;
    DWORD dwAllocationGranularity;
    WORD wProcessorLevel;
    WORD wProcessorRevision;
};

// MEMORY_BASIC_INFORMATION struct.
struct MEMORY_BASIC_INFORMATION {
    LPVOID BaseAddress;
    LPVOID AllocationBase;
    DWORD AllocationProtect;
    SIZE_T RegionSize;
    DWORD State;
    DWORD Protect;
    DWORD Type;
};

// таблица внутрянки для ВАП'а
struct InternalRegion {
    uintptr_t start;
    uintptr_t end;
    DWORD state;
    DWORD protect;
    DWORD type;
};

std::vector<InternalRegion> g_regions;
LPVOID g_demoBuffer = nullptr;
SIZE_T g_pageSize = 4096;

// 1. GetSystemInfo()
void GetSystemInfo(SYSTEM_INFO* lpSystemInfo) {
    if (!lpSystemInfo) return;
    std::memset(lpSystemInfo, 0, sizeof(SYSTEM_INFO));

    long pageSize = sysconf(_SC_PAGESIZE);
    if (pageSize <= 0) pageSize = 4096;
    g_pageSize = static_cast<SIZE_T>(pageSize);

    long numProcs = sysconf(_SC_NPROCESSORS_ONLN);
    if (numProcs <= 0) numProcs = 1;

    lpSystemInfo->wProcessorArchitecture = 9; // PROCESSOR_ARCHITECTURE_AMD64
    lpSystemInfo->dwPageSize = static_cast<DWORD>(g_pageSize);
    lpSystemInfo->lpMinimumApplicationAddress = reinterpret_cast<LPVOID>(0x0000000000010000ULL);
    lpSystemInfo->lpMaximumApplicationAddress = reinterpret_cast<LPVOID>(0x00007FFFFFFEFFFFULL);
    lpSystemInfo->dwNumberOfProcessors = static_cast<DWORD>(numProcs);
    lpSystemInfo->dwAllocationGranularity = 65536; // 64 КБ для WinAPI
}

// данные о реальном виртуальном адресном пространстве процесса (для Linux/macOS/APE runtime)
void RefreshMemoryMap() {
    g_regions.clear();
    std::ifstream maps("/proc/self/maps");

    if (maps.is_open()) {
        // Если запущено на Linux (или в среде с /proc/self/maps) — тогда парсю реальную карту памяти ОС
        std::string line;
        uintptr_t lastEnd = 0x10000;

        while (std::getline(maps, line)) {
            std::istringstream iss(line);
            std::string addrRange, perms, offset, dev, inode, pathname;
            iss >> addrRange >> perms >> offset >> dev >> inode;
            std::getline(iss, pathname);

            size_t dashPos = addrRange.find('-');
            if (dashPos == std::string::npos) continue;

            uintptr_t start = std::stoull(addrRange.substr(0, dashPos), nullptr, 16);
            uintptr_t end = std::stoull(addrRange.substr(dashPos + 1), nullptr, 16);

            if (start > lastEnd) {
                g_regions.push_back({lastEnd, start, MEM_FREE, PAGE_NOACCESS, 0});
            }

            DWORD prot = PAGE_NOACCESS;
            bool r = (perms.size() > 0 && perms[0] == 'r');
            bool w = (perms.size() > 1 && perms[1] == 'w');
            bool x = (perms.size() > 2 && perms[2] == 'x');

            if (r && w && x) prot = PAGE_EXECUTE_READWRITE;
            else if (r && x) prot = PAGE_EXECUTE_READ;
            else if (x)      prot = PAGE_EXECUTE;
            else if (r && w) prot = PAGE_READWRITE;
            else if (r)      prot = PAGE_READONLY;

            DWORD type = MEM_PRIVATE;
            if (!pathname.empty() && pathname.find('/') != std::string::npos) {
                type = MEM_IMAGE;
            } else if (perms.size() > 3 && perms[3] == 's') {
                type = MEM_MAPPED;
            }

            g_regions.push_back({start, end, MEM_COMMIT, prot, type});
            lastEnd = end;
        }
        if (lastEnd < 0x00007FFFFFFEFFFFULL) {
            g_regions.push_back({lastEnd, 0x00007FFFFFFEFFFFULL, MEM_FREE, PAGE_NOACCESS, 0});
        }
    } else {
        // Fallback для macOS и Windows (под управлением APE runtime) на основе реальных адресов секций процесса
        uintptr_t codeAddr = reinterpret_cast<uintptr_t>(&GetSystemInfo) & ~(g_pageSize - 1);
        uintptr_t stackVar = 0;
        uintptr_t stackAddr = reinterpret_cast<uintptr_t>(&stackVar) & ~(g_pageSize - 1);
        uintptr_t demoAddr = reinterpret_cast<uintptr_t>(g_demoBuffer);

        g_regions.push_back({0x10000ULL, codeAddr, MEM_FREE, PAGE_NOACCESS, 0});
        g_regions.push_back({codeAddr, codeAddr + g_pageSize * 16, MEM_COMMIT, PAGE_EXECUTE_READ, MEM_IMAGE});

        if (demoAddr > codeAddr + g_pageSize * 16) {
            g_regions.push_back({codeAddr + g_pageSize * 16, demoAddr, MEM_FREE, PAGE_NOACCESS, 0});
            g_regions.push_back({demoAddr, demoAddr + g_pageSize, MEM_COMMIT, PAGE_READWRITE, MEM_PRIVATE});
            g_regions.push_back({demoAddr + g_pageSize, demoAddr + g_pageSize * 2, MEM_COMMIT, PAGE_READONLY, MEM_PRIVATE});
            g_regions.push_back({demoAddr + g_pageSize * 2, demoAddr + g_pageSize * 4, MEM_RESERVE, PAGE_NOACCESS, MEM_PRIVATE});
            if (stackAddr > demoAddr + g_pageSize * 4) {
                g_regions.push_back({demoAddr + g_pageSize * 4, stackAddr - g_pageSize * 8, MEM_FREE, PAGE_NOACCESS, 0});
                g_regions.push_back({stackAddr - g_pageSize * 8, stackAddr + g_pageSize * 2, MEM_COMMIT, PAGE_READWRITE, MEM_PRIVATE});
            }
        }
        uintptr_t endLast = g_regions.back().end;
        if (endLast < 0x00007FFFFFFEFFFFULL) {
            g_regions.push_back({endLast, 0x00007FFFFFFEFFFFULL, MEM_FREE, PAGE_NOACCESS, 0});
        }
    }
}

// 2. VirtualQuery()
SIZE_T VirtualQuery(LPCVOID lpAddress, MEMORY_BASIC_INFORMATION* lpBuffer, SIZE_T dwLength) {
    if (!lpBuffer || dwLength < sizeof(MEMORY_BASIC_INFORMATION)) return 0;

    uintptr_t addr = reinterpret_cast<uintptr_t>(lpAddress);
    uintptr_t pageAligned = addr & ~(g_pageSize - 1);

    for (const auto& reg : g_regions) {
        if (pageAligned >= reg.start && pageAligned < reg.end) {
            lpBuffer->BaseAddress = reinterpret_cast<LPVOID>(pageAligned);
            lpBuffer->AllocationBase = (reg.state == MEM_FREE) ? nullptr : reinterpret_cast<LPVOID>(reg.start);
            lpBuffer->AllocationProtect = reg.protect;
            lpBuffer->RegionSize = reg.end - pageAligned;
            lpBuffer->State = reg.state;
            lpBuffer->Protect = reg.protect;
            lpBuffer->Type = reg.type;
            return sizeof(MEMORY_BASIC_INFORMATION);
        }
    }
    return 0;
}

// 3. VirtualProtect()
BOOL VirtualProtect(LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, DWORD* lpflOldProtect) {
    if (!lpAddress || dwSize == 0) return 0;

    uintptr_t addr = reinterpret_cast<uintptr_t>(lpAddress);
    uintptr_t alignedAddr = addr & ~(g_pageSize - 1);
    SIZE_T alignedSize = ((dwSize + (addr - alignedAddr) + g_pageSize - 1) / g_pageSize) * g_pageSize;

    int posixProt = PROT_NONE;
    if (flNewProtect == PAGE_READONLY) posixProt = PROT_READ;
    else if (flNewProtect == PAGE_READWRITE || flNewProtect == PAGE_WRITECOPY) posixProt = PROT_READ | PROT_WRITE;
    else if (flNewProtect == PAGE_EXECUTE) posixProt = PROT_EXEC;
    else if (flNewProtect == PAGE_EXECUTE_READ) posixProt = PROT_READ | PROT_EXEC;
    else if (flNewProtect == PAGE_EXECUTE_READWRITE) posixProt = PROT_READ | PROT_WRITE | PROT_EXEC;

    if (mprotect(reinterpret_cast<void*>(alignedAddr), alignedSize, posixProt) != 0) {
        return 0;
    }

    // Обновление внутренней таблицы регионов
    for (auto& reg : g_regions) {
        if (alignedAddr >= reg.start && alignedAddr < reg.end) {
            if (lpflOldProtect) *lpflOldProtect = reg.protect;
            reg.protect = flNewProtect;
            break;
        }
    }
    return 1;
}

// Вспомогательные функции форматирования вывода
std::string StateToString(DWORD state) {
    switch (state) {
        case MEM_COMMIT:  return "MEM_COMMIT  (Занята/Физ.память)";
        case MEM_RESERVE: return "MEM_RESERVE (Зарезервирована)";
        case MEM_FREE:    return "MEM_FREE    (Свободна)";
        default:          return "UNKNOWN";
    }
}

std::string ProtectToString(DWORD protect, DWORD state) {
    if (state == MEM_FREE) return "PAGE_NOACCESS (Нет доступа)";
    switch (protect) {
        case PAGE_NOACCESS:          return "PAGE_NOACCESS (Запрет доступа)";
        case PAGE_READONLY:          return "PAGE_READONLY (Только чтение)";
        case PAGE_READWRITE:         return "PAGE_READWRITE (Чтение и запись)";
        case PAGE_WRITECOPY:         return "PAGE_WRITECOPY (Копирование при записи)";
        case PAGE_EXECUTE:           return "PAGE_EXECUTE (Исполнение кода)";
        case PAGE_EXECUTE_READ:      return "PAGE_EXECUTE_READ (Исполнение и чтение)";
        case PAGE_EXECUTE_READWRITE: return "PAGE_EXECUTE_READWRITE (Полный доступ)";
        default:                     return "OTHER_PROTECT";
    }
}

std::string TypeToString(DWORD type, DWORD state) {
    if (state == MEM_FREE) return "-";
    switch (type) {
        case MEM_IMAGE:   return "MEM_IMAGE   (Исполняемый модуль)";
        case MEM_MAPPED:  return "MEM_MAPPED  (Проецируемый файл)";
        case MEM_PRIVATE: return "MEM_PRIVATE (Приватная память)";
        default:          return "-";
    }
}

// Округление адреса вниз до границы страницы (требование п.1 задания)
uintptr_t AlignDownToPage(uintptr_t address, DWORD pageSize) {
    return address & ~(static_cast<uintptr_t>(pageSize) - 1);
}

int main() {
    SYSTEM_INFO sysInfo;
    GetSystemInfo(&sysInfo);

    g_demoBuffer = mmap(nullptr, sysInfo.dwPageSize * 4, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (g_demoBuffer != MAP_FAILED) {
        mprotect(static_cast<char*>(g_demoBuffer) + sysInfo.dwPageSize, sysInfo.dwPageSize, PROT_READ);
    }

    RefreshMemoryMap();

    while (true) {
        std::cout << "\n====================================================================\n";
        std::cout << "   ИССЛЕДОВАНИЕ ОБЛАСТЕЙ ВИРТУАЛЬНОЙ ПАМЯТИ (ВАРИАНТ 2)\n";
        std::cout << "====================================================================\n";
        std::cout << "1. Вывести параметры системы и границы ВАП (GetSystemInfo)\n";
        std::cout << "2. Исследовать одиночный адрес памяти (округление вниз + VirtualQuery)\n";
        std::cout << "3. Сканировать диапазон регионов памяти (перебор через VirtualQuery)\n";
        std::cout << "4. Управление защитой и отладочная страница (VirtualProtect)\n";
        std::cout << "0. Выход\n";
        std::cout << "--------------------------------------------------------------------\n";
        std::cout << "Выберите действие: ";

        int choice = 0;
        if (!(std::cin >> choice)) {
            std::cin.clear();
            std::cin.ignore(10000, '\n');
            continue;
        }

        if (choice == 0) break;

        if (choice == 1) {
            std::cout << "\n[Системная информация и границы ВАП процесса]\n";
            std::cout << "Размер страницы виртуальной памяти : " << sysInfo.dwPageSize << " байт (" << sysInfo.dwPageSize / 1024 << " КБ)\n";
            std::cout << "Гранулярность выделения памяти     : " << sysInfo.dwAllocationGranularity << " байт\n";
            std::cout << "Минимальный адрес ВАП              : 0x" << std::hex << std::uppercase << std::setw(16) << std::setfill('0')
                      << reinterpret_cast<uintptr_t>(sysInfo.lpMinimumApplicationAddress) << std::dec << "\n";
            std::cout << "Максимальный адрес ВАП             : 0x" << std::hex << std::uppercase << std::setw(16) << std::setfill('0')
                      << reinterpret_cast<uintptr_t>(sysInfo.lpMaximumApplicationAddress) << std::dec << "\n";
            std::cout << "Количество логических процессоров  : " << sysInfo.dwNumberOfProcessors << "\n";
            std::cout << "Адрес тестового буфера в процессе  : 0x" << std::hex << std::uppercase
                      << reinterpret_cast<uintptr_t>(g_demoBuffer) << std::dec << "\n";
        }
        else if (choice == 2) {
            std::cout << "\nВведите исследуемый адрес в HEX (например, "
                      << std::hex << (reinterpret_cast<uintptr_t>(g_demoBuffer) + 0x123) << std::dec << "): 0x";
            uintptr_t inputAddr = 0;
            std::cin >> std::hex >> inputAddr >> std::dec;

            uintptr_t alignedAddr = AlignDownToPage(inputAddr, sysInfo.dwPageSize);
            std::cout << "\nВведенный адрес                    : 0x" << std::hex << std::uppercase << inputAddr << "\n";
            std::cout << "Округленный вниз (кратно " << std::dec << sysInfo.dwPageSize << " Б) : 0x"
                      << std::hex << std::uppercase << alignedAddr << std::dec << "\n";

            MEMORY_BASIC_INFORMATION mbi;
            if (VirtualQuery(reinterpret_cast<LPCVOID>(alignedAddr), &mbi, sizeof(mbi))) {
                std::cout << "Базовый адрес страницы (BaseAddr)  : 0x" << std::hex << reinterpret_cast<uintptr_t>(mbi.BaseAddress) << "\n";
                std::cout << "Базовый адрес региона (AllocBase)  : 0x" << reinterpret_cast<uintptr_t>(mbi.AllocationBase) << std::dec << "\n";
                std::cout << "Размер региона от текущей страницы : " << mbi.RegionSize << " байт (" << (mbi.RegionSize / 1024) << " КБ)\n";
                std::cout << "Состояние страницы (State)         : " << StateToString(mbi.State) << "\n";
                std::cout << "Атрибуты защиты (Protect)          : " << ProtectToString(mbi.Protect, mbi.State) << "\n";
                std::cout << "Тип памяти (Type)                  : " << TypeToString(mbi.Type, mbi.State) << "\n";
            } else {
                std::cout << "Ошибка: адрес выходит за пределы доступного ВАП.\n";
            }
        }
        else if (choice == 3) {
            uintptr_t defaultStart = reinterpret_cast<uintptr_t>(sysInfo.lpMinimumApplicationAddress);
            uintptr_t defaultEnd   = reinterpret_cast<uintptr_t>(sysInfo.lpMaximumApplicationAddress);

            std::cout << "\n1 - Сканировать всё ВАП процесса (от 0x" << std::hex << defaultStart << " до 0x" << defaultEnd << ")\n";
            std::cout << "2 - Ввести собственный диапазон начального и конечного адресов\n";
            std::cout << "Ваш выбор: ";
            int sub = 1;
            std::cin >> sub;

            uintptr_t startAddr = defaultStart;
            uintptr_t endAddr   = defaultEnd;

            if (sub == 2) {
                std::cout << "Начальный адрес (HEX): 0x";
                std::cin >> std::hex >> startAddr;
                std::cout << "Конечный адрес  (HEX): 0x";
                std::cin >> std::hex >> endAddr >> std::dec;
            }

            uintptr_t currentAddr = AlignDownToPage(startAddr, sysInfo.dwPageSize);
            std::cout << "\nНачальный адрес после округления вниз: 0x" << std::hex << std::uppercase << currentAddr << std::dec << "\n\n";

            std::cout << std::left
                      << std::setw(20) << "Базовый адрес"
                      << std::setw(16) << "Размер (КБ)"
                      << std::setw(32) << "Состояние (MEM_*)"
                      << std::setw(35) << "Защита (PAGE_*)"
                      << "Тип" << "\n";
            std::cout << std::string(120, '-') << "\n";

            MEMORY_BASIC_INFORMATION mbi;
            int shown = 0;
            while (currentAddr < endAddr && VirtualQuery(reinterpret_cast<LPCVOID>(currentAddr), &mbi, sizeof(mbi)) != 0) {
                std::ostringstream addrStr;
                addrStr << "0x" << std::hex << std::uppercase << std::setw(14) << std::setfill('0')
                        << reinterpret_cast<uintptr_t>(mbi.BaseAddress);

                std::cout << std::left << std::setfill(' ')
                          << std::setw(20) << addrStr.str()
                          << std::setw(16) << (mbi.RegionSize / 1024)
                          << std::setw(32) << StateToString(mbi.State)
                          << std::setw(35) << ProtectToString(mbi.Protect, mbi.State)
                          << TypeToString(mbi.Type, mbi.State) << "\n";

                uintptr_t nextAddr = reinterpret_cast<uintptr_t>(mbi.BaseAddress) + mbi.RegionSize;
                if (nextAddr <= currentAddr) break;
                currentAddr = nextAddr;

                if (++shown >= 25) {
                    std::cout << "... (показаны первые 25 регионов для читаемости таблицы) ...\n";
                    break;
                }
            }
        }
        else if (choice == 4) {
            uintptr_t workPage  = reinterpret_cast<uintptr_t>(g_demoBuffer);
            uintptr_t guardPage = workPage + sysInfo.dwPageSize;

            std::cout << "\n[Демонстрация управления защитой VirtualProtect и отладочной страницы]\n";
            std::cout << "Рабочая страница (Page 1)    : 0x" << std::hex << workPage << " (PAGE_READWRITE)\n";
            std::cout << "Сторожевая страница (Page 2) : 0x" << guardPage << " (PAGE_READONLY — сразу после выделенной)\n\n" << std::dec;

            MEMORY_BASIC_INFORMATION mbi;
            VirtualQuery(reinterpret_cast<LPCVOID>(workPage), &mbi, sizeof(mbi));
            std::cout << "Текущая защита рабочей страницы : " << ProtectToString(mbi.Protect, mbi.State) << "\n";

            std::cout << "-> Вызываем VirtualProtect() для смены защиты на PAGE_EXECUTE_READ...\n";
            DWORD oldProtect = 0;
            if (VirtualProtect(reinterpret_cast<LPVOID>(workPage), sysInfo.dwPageSize, PAGE_EXECUTE_READ, &oldProtect)) {
                VirtualQuery(reinterpret_cast<LPCVOID>(workPage), &mbi, sizeof(mbi));
                std::cout << "Успешно! Старая защита: " << ProtectToString(oldProtect, MEM_COMMIT) << "\n";
                std::cout << "Новая защита (по данным VirtualQuery): " << ProtectToString(mbi.Protect, mbi.State) << "\n";
            }

            std::cout << "-> Возвращаем защиту PAGE_READWRITE и выполняем безопасную затирку памяти (0x00)...\n";
            VirtualProtect(reinterpret_cast<LPVOID>(workPage), sysInfo.dwPageSize, PAGE_READWRITE, &oldProtect);
            volatile uint8_t* ptr = reinterpret_cast<volatile uint8_t*>(workPage);
            for (SIZE_T i = 0; i < sysInfo.dwPageSize; ++i) ptr[i] = 0;
            std::cout << "Остаточная информация в рабочей странице успешно очищена.\n";
        }
    }

    if (g_demoBuffer && g_demoBuffer != MAP_FAILED) {
        munmap(g_demoBuffer, sysInfo.dwPageSize * 4);
    }
    return 0;
}
