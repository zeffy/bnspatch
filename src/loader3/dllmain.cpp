#include "pch.h"
#include <delayimp.h>
#pragma comment( lib, "delayimp.lib" )

#include "hooks.h"
#include "wl.h"

static inline volatile auto g_pfnSHCreateProcessAsUserW = &SHCreateProcessAsUserW;

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
  switch ( ul_reason_for_call ) {
    case DLL_PROCESS_ATTACH: {
      NtCurrentPeb()->BeingDebugged = FALSE;

      wil::unique_handle tokenHandle;
      THROW_IF_WIN32_BOOL_FALSE(OpenProcessToken(NtCurrentProcess(), TOKEN_WRITE, &tokenHandle));
      ULONG virtualizationEnabled = TRUE;
      THROW_IF_WIN32_BOOL_FALSE(SetTokenInformation(tokenHandle.get(), TokenVirtualizationEnabled, &virtualizationEnabled, sizeof(ULONG)));

      THROW_IF_WIN32_ERROR(DetourTransactionBegin());
      THROW_IF_WIN32_ERROR(DetourUpdateThread(NtCurrentThread()));
      const auto hNtDll = GetModuleHandleW(RtlNtdllName);
      THROW_LAST_ERROR_IF_NULL(hNtDll);

      g_pfnNtQueryInformationProcess = GetProcAddressByFunctionDeclaration(hNtDll, NtQueryInformationProcess);
      THROW_LAST_ERROR_IF_NULL(g_pfnNtQueryInformationProcess);
      if ( WLIsProtected() ) {
        THROW_IF_WIN32_ERROR(DetourAttach(hNtDll, "LdrGetDllHandle", g_pfnLdrGetDllHandle, LdrGetDllHandle_hook));
        THROW_IF_WIN32_ERROR(DetourAttach(hNtDll, "NtCreateThreadEx", g_pfnNtCreateThreadEx, NtCreateThreadEx_hook));
        THROW_IF_WIN32_ERROR(DetourAttach(hNtDll, "NtGetContextThread", g_pfnNtGetContextThread, NtGetContextThread_hook));
        THROW_IF_WIN32_ERROR(DetourAttach(hNtDll, "NtOpenKeyEx", g_pfnNtOpenKeyEx, NtOpenKeyEx_hook));
        THROW_IF_WIN32_ERROR(DetourAttach(hNtDll, "NtProtectVirtualMemory", g_pfnNtProtectVirtualMemory, NtProtectVirtualMemory_hook));
#ifdef _WIN64
        THROW_IF_WIN32_ERROR(DetourAttach(g_pfnNtQueryInformationProcess, NtQueryInformationProcess_hook));
        THROW_IF_WIN32_ERROR(DetourAttach(hNtDll, "NtSetInformationThread", g_pfnNtSetInformationThread, NtSetInformationThread_hook));
#endif
        THROW_IF_WIN32_ERROR(DetourAttach(L"user32.dll", "FindWindowA", g_pfnFindWindowA, FindWindowA_hook));
      }
      THROW_IF_WIN32_ERROR(DetourAttach(hNtDll, "LdrLoadDll", g_pfnLdrLoadDll, LdrLoadDll_hook));
      THROW_IF_WIN32_ERROR(DetourAttach(hNtDll, "NtCreateFile", g_pfnNtCreateFile, NtCreateFile_hook));
      THROW_IF_WIN32_ERROR(DetourAttach(hNtDll, "NtCreateMutant", g_pfnNtCreateMutant, NtCreateMutant_hook));
      THROW_IF_WIN32_ERROR(DetourAttach(hNtDll, "NtQuerySystemInformation", g_pfnNtQuerySystemInformation, NtQuerySystemInformation_hook));
      THROW_IF_WIN32_ERROR(DetourAttach(L"kernel32.dll", "GetSystemTimeAsFileTime", g_pfnGetSystemTimeAsFileTime, GetSystemTimeAsFileTime_hook));
      THROW_IF_WIN32_ERROR(DetourTransactionCommit());
      break;
    }
  }
  return TRUE;
}

const PfnDliHook __pfnDliNotifyHook2 = [](unsigned dliNotify, PDelayLoadInfo pdli) -> FARPROC {
  switch ( dliNotify ) {
    case dliNotePreLoadLibrary: {
      std::wstring result;
      THROW_IF_NTSTATUS_FAILED(wil::GetSystemDirectoryW(result));
      std::filesystem::path path{std::move(result)};
      path /= pdli->szDll;
      return reinterpret_cast<FARPROC>(LoadLibraryExW(path.c_str(), nullptr, LOAD_WITH_ALTERED_SEARCH_PATH));
    }
  }
  return nullptr;
};
