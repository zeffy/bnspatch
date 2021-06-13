#pragma once
#include <phnt_windows.h>
#include <phnt.h>
#include "pluginsdk.h"

extern decltype(&GetSystemTimeAsFileTime) g_pfnGetSystemTimeAsFileTime;
VOID WINAPI GetSystemTimeAsFileTime_hook(LPFILETIME lpSystemTimeAsFileTime);

extern decltype(&RtlLeaveCriticalSection) g_pfnRtlLeaveCriticalSection;
NTSTATUS NTAPI RtlLeaveCriticalSection_hook(PRTL_CRITICAL_SECTION CriticalSection);
