#include "helper.hpp"

whandle::whandle()
    : h(NULL)
{
}

whandle::whandle(HANDLE hnd)
    : h(hnd)
{
}

whandle::~whandle()
{
    if (this->h)
        CloseHandle(this->h);
}

auto whandle::close() const noexcept -> void
{
    if (this->h)
    {
        CloseHandle(this->h);
        this->h = nullptr;
    }
}

whandle::operator bool() const noexcept
{
    return this->h != nullptr && this->h != INVALID_HANDLE_VALUE;
}

whandle::operator HANDLE() const noexcept
{
    return this->h;
}

auto whandle::operator=(HANDLE hnd) noexcept -> HANDLE
{
    this->close();
    this->h = hnd;
    return hnd;
}