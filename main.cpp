#include <Windows.h>
#include <cstdio>
#include <tlhelp32.h>
#include <functional>
#include <vector>
#include <memory>
#include <iostream>
#include "helper.hpp"

auto find_osu(DWORD & outpid) -> bool
{
    whandle psnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
    PROCESSENTRY32 pe { .dwSize { sizeof(pe) } };
    if (Process32First(psnap, &pe))
    {
        do
        {
            if (strcmp(pe.szExeFile, "osu!.exe") == 0)
            {
                outpid = pe.th32ProcessID;
                return true;
            }
        } while (Process32Next(psnap, &pe));
    }

    return false;
}

enum class THREAD_DO
{
    SUSPEND,
    RESUME
};

auto thread_cont(DWORD proc_id, THREAD_DO tdo) -> void
{
    auto * act = tdo == THREAD_DO::SUSPEND ? SuspendThread : ResumeThread;

    whandle tsnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, NULL);
    if (!tsnap)
        return;

    THREADENTRY32 te { .dwSize { sizeof(te) } };
    if (Thread32First(tsnap, &te))
    {
        do
        {
            if (te.th32OwnerProcessID == proc_id)
            {
                whandle th = OpenThread(THREAD_SUSPEND_RESUME, FALSE, te.th32ThreadID);
                act(th);
            }
        } while(Thread32Next(tsnap, &te));
    }
}

auto __enumerate_memory_default_filter(PMEMORY_BASIC_INFORMATION mbi) -> bool
{
    if (mbi->State == MEM_COMMIT && mbi->Protect & (PAGE_READONLY | PAGE_READWRITE))
        return false;

    return true;
}

template <typename T>
auto enumerate_memory(whandle & hnd, T callback, bool(*filter)(PMEMORY_BASIC_INFORMATION) = __enumerate_memory_default_filter) -> bool
{
    std::uintptr_t current { 0 };
    MEMORY_BASIC_INFORMATION mbi {};
    while (VirtualQueryEx(hnd, LPCVOID(current), &mbi, sizeof(mbi)))
    {
        if (!filter(&mbi) && !callback(current, &mbi))
            return true;

        current += mbi.RegionSize;
    }

    return true;
}

auto wchar_search(const wchar_t * to_search, void * buffer, std::size_t size) -> wchar_t *
{
    auto len = wcslen(to_search);
    auto end_of_buffer = reinterpret_cast<wchar_t *>(std::uintptr_t(buffer) + size - (len * sizeof(wchar_t)));

    for (auto buffer_index = reinterpret_cast<wchar_t *>(buffer); buffer_index < end_of_buffer; ++buffer_index)
    {
        for (int match_index = 0; match_index < len; ++match_index)
        {
            if (to_search[match_index] != buffer_index[match_index])
                break;

            if (match_index == len - 1)
                return buffer_index;
        }
    }

    return nullptr;
}

class raii_resume_osu
{
public:
    raii_resume_osu(DWORD pid_)
        : pid(pid_) {}

    ~raii_resume_osu()
    {
        printf("\n[+] Resuming osu");
        thread_cont(pid, THREAD_DO::RESUME);
    }

private:
    DWORD pid;
};

#define WAIT_FOR_EVAL(evaluate, ...) \
    while (!evaluate(__VA_ARGS__)) Sleep(800)

auto main() -> int
{
    // Find osu proc
    printf("\n[+] Looking for osu");
    DWORD osu_pid;
    if (!find_osu(osu_pid))
    {
        printf("\n[!] osu!.exe not found!");
        return 1;
    }
    printf(" -> %d", osu_pid);

    // Open handle
    printf("\n[+] Opening handle");
    whandle osu_proc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, osu_pid);
    if (!osu_proc)
    {
        printf("\n[!] Failed to open handle!");
        return 1;
    }
    printf(" -> 0x%p", HANDLE(osu_proc));

    // Suspend all osu related threads
    printf("\n[+] Suspending osu...");
    thread_cont(osu_pid, THREAD_DO::SUSPEND);

    // Create RAII object to resume osu automatically
    auto osu_res = raii_resume_osu(osu_pid);

    // Count how much buffer we need
    printf("\n[+] Querying readable memory size");
    std::size_t buffer_size { 0 };
    std::vector<std::pair<std::uintptr_t, DWORD>> readable_memory;
    enumerate_memory(osu_proc, [&](auto current, auto mbi) -> bool
    {
        buffer_size += mbi->RegionSize;
        readable_memory.emplace_back(current, mbi->RegionSize);
        return true;
    });
    printf(" -> %llu bytes", buffer_size);

    // Allocate buffer
    auto buffer = std::make_unique<std::uint8_t[]>(buffer_size);

    // Load readable memory into buffer
    printf("\n");
    auto current_buffer = buffer.get();
    std::size_t total_bytes_read {0 };
    for (const auto & [adr, size] : readable_memory)
    {
        printf("\n[+] Reading to buffer @ 0x%p (%lu bytes)", adr, size);
        if (!ReadProcessMemory(osu_proc, LPCVOID(adr), current_buffer, size, nullptr))
        {
            printf("\n[!] Invalid memory read @ 0x%p! Ignoring", adr);
            continue;
        }

        total_bytes_read += size;
        current_buffer += size;
    }

    printf("\n[+] Readable sections dumped! (with %d bytes of wasted memory!)", buffer_size - total_bytes_read);

    // Look for version
    printf("\n[+] Looking for version");
    #define _OSU_VER_PATTERN L"https://osu.ppy.sh/home/changelog/"
    auto link_res = wchar_search(_OSU_VER_PATTERN, buffer.get(), total_bytes_read);
    if (!link_res)
    {
        printf("\n[!] No version reference found!"
               "\n[I] Open settings and scroll down, once you see the version text click on it atleast once. (This just gets the memory warm and ready for dumping!)");
        return 0;
    }

    // Parse for version
    printf("\n[+] Parsing version");
    wchar_t version[64] {};
    link_res += sizeof(_OSU_VER_PATTERN) / 2 - 1;
    for (auto p_ver = version; *link_res != 0 && *link_res != '.' && *link_res != '-'; ++p_ver, ++link_res)
    {
        *p_ver = *link_res;
    }
    wprintf(L" -> %s", version);
    #undef _OSU_VER_PATTERN

    // Look for the key
    printf("\n[+] Looking for key");
    wchar_t key[64] {};
    void * current = buffer.get();
    wchar_t * key_loc = nullptr;
    while (auto key_res = wchar_search(version, current, total_bytes_read - (std::uintptr_t(current) - std::uintptr_t(buffer.get())) ))
    {
        if (*(key_res - 1) != '-')
        {
            current = key_res + 1;
            continue;
        }

        key_loc = reinterpret_cast<wchar_t *>(key_res);
        break;
    }

    if (!key_loc)
    {
        printf("\n[!] No references to the decryption key found!");
        return 1;
    }

    // Parse key
    printf("\n[+] Parsing key");
    while (*key_loc--);
    key_loc += 2;
    for (auto p_key = key; *key_loc != 0 && *key_loc != '-'; ++p_key, ++key_loc)
    {
        *p_key = *key_loc;
    }
    wprintf(L" -> %s", key);

    return 0;
}