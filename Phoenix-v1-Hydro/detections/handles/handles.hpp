#pragma once

#include <Windows.h>
#include <vector>

namespace detections::handles
{
    std::vector<DWORD> scan(DWORD target_pid, DWORD self_pid);
}
