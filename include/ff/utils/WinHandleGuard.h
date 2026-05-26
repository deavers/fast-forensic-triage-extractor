#pragma once
#include "ff/Platform.h"

#ifdef FF_PLATFORM_WINDOWS
#include <windows.h>
#include <memory>

namespace ff::utils
{
    struct HandleDeleter
    {
        void operator()(HANDLE h) const
        {
            if (h != nullptr && h != INVALID_HANDLE_VALUE)
            {
                CloseHandle(h);
            }
        }
    };

    using UniqueHandle = std::unique_ptr<void, HandleDeleter>;

    inline UniqueHandle makeHandle(HANDLE h)
    {
        if (h == INVALID_HANDLE_VALUE)
        {
            return UniqueHandle(nullptr);
        }
        return UniqueHandle(h);
    }
}

#endif // FF_PLATFORM_WINDOWS