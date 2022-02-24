#pragma once

#include <Windows.h>

class whandle
{
public:
    whandle(const whandle &) = delete;
    whandle(whandle &&) = delete;

    whandle();
    whandle(HANDLE hnd);
    ~whandle();

    auto close() const noexcept -> void;

    operator bool() const noexcept;
    operator HANDLE() const noexcept;
    auto operator =(HANDLE hnd) noexcept -> HANDLE;

private:
    mutable HANDLE h; // lol
};