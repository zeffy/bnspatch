#include "pch.h"
#include <delayimp.h>
#include "globals.h"
#include "hooks.h"
#include "pluginsdk.h"

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
  switch ( ul_reason_for_call ) {
    case DLL_PROCESS_ATTACH: {
      THROW_IF_WIN32_BOOL_FALSE(DisableThreadLibraryCalls(hModule));

      const auto resInfo = FindResourceW(nullptr, MAKEINTRESOURCEW(VS_VERSION_INFO), VS_FILE_INFO);
      if ( !resInfo ) return TRUE;

      const auto count = SizeofResource(nullptr, resInfo);
      if ( !count ) return TRUE;

      const auto ptr = LoadResource(nullptr, resInfo);
      if ( !ptr ) return TRUE;

      const std::span res{reinterpret_cast<PUCHAR>(ptr), count};
      const std::vector<UCHAR> block{res.begin(), res.end()};

      struct LANGANDCODEPAGE
      {
        WORD wLanguage;
        WORD wCodePage;
      };
      LPVOID buffer;
      UINT len;
      if ( VerQueryValueW(block.data(), L"\\VarFileInfo\\Translation", &buffer, &len) ) {
        for ( const auto &t : std::span{static_cast<LANGANDCODEPAGE *>(buffer), len / sizeof(LANGANDCODEPAGE)} ) {
          const auto subBlock = std::format(L"\\StringFileInfo\\{:04x}{:04x}\\OriginalFilename", t.wLanguage, t.wCodePage);

          if ( !VerQueryValueW(block.data(), subBlock.c_str(), &buffer, &len) )
            continue;

          const std::wstring_view originalFilename{static_cast<LPCWSTR>(buffer), len - 1};
          if ( originalFilename == L"Client.exe"sv || originalFilename == L"BNSR.exe"sv ) {
            NtCurrentPeb()->BeingDebugged = FALSE;

            if ( VerQueryValueW(block.data(), L"\\", &buffer, &len) && len == sizeof(VS_FIXEDFILEINFO) ) {
              const auto vsf = static_cast<VS_FIXEDFILEINFO *>(buffer);
              GClientVersion = (static_cast<uint64_t>(vsf->dwProductVersionMS) << 32) | vsf->dwProductVersionLS;
            }
            wil::unique_handle tokenHandle;
            THROW_IF_WIN32_BOOL_FALSE(OpenProcessToken(NtCurrentProcess(), TOKEN_WRITE, &tokenHandle));
            ULONG virtualizationEnabled = TRUE;
            THROW_IF_WIN32_BOOL_FALSE(SetTokenInformation(tokenHandle.get(), TokenVirtualizationEnabled, &virtualizationEnabled, sizeof(ULONG)));

            THROW_IF_WIN32_ERROR(DetourTransactionBegin());
            THROW_IF_WIN32_ERROR(DetourUpdateThread(NtCurrentThread()));
            const auto hNtDll = GetModuleHandleW(RtlNtdllName);
            THROW_LAST_ERROR_IF_NULL(hNtDll);
            THROW_IF_WIN32_ERROR(DetourAttach(hNtDll, "LdrGetDllHandle", &g_pfnLdrGetDllHandle, LdrGetDllHandle_hook));
            THROW_IF_WIN32_ERROR(DetourAttach(hNtDll, "LdrLoadDll", &g_pfnLdrLoadDll, LdrLoadDll_hook));
            THROW_IF_WIN32_ERROR(DetourAttach(hNtDll, "NtCreateFile", &g_pfnNtCreateFile, NtCreateFile_hook));
            THROW_IF_WIN32_ERROR(DetourAttach(hNtDll, "NtCreateMutant", &g_pfnNtCreateMutant, NtCreateMutant_hook));
            THROW_IF_WIN32_ERROR(DetourAttach(hNtDll, "NtCreateThreadEx", &g_pfnNtCreateThreadEx, NtCreateThreadEx_hook));
            THROW_IF_WIN32_ERROR(DetourAttach(hNtDll, "NtGetContextThread", &g_pfnNtGetContextThread, NtGetContextThread_hook));
            THROW_IF_WIN32_ERROR(DetourAttach(hNtDll, "NtOpenKeyEx", &g_pfnNtOpenKeyEx, NtOpenKeyEx_hook));
            THROW_IF_WIN32_ERROR(DetourAttach(hNtDll, "NtProtectVirtualMemory", &g_pfnNtProtectVirtualMemory, NtProtectVirtualMemory_hook));
            THROW_IF_WIN32_ERROR(DetourAttach(hNtDll, "NtQueryInformationProcess", &g_pfnNtQueryInformationProcess, NtQueryInformationProcess_hook));
            THROW_IF_WIN32_ERROR(DetourAttach(hNtDll, "NtQuerySystemInformation", &g_pfnNtQuerySystemInformation, NtQuerySystemInformation_hook));
            THROW_IF_WIN32_ERROR(DetourAttach(hNtDll, "NtSetInformationThread", &g_pfnNtSetInformationThread, NtSetInformationThread_hook));
            THROW_IF_WIN32_ERROR(DetourAttach(hNtDll, "RtlLeaveCriticalSection", &g_pfnRtlLeaveCriticalSection, RtlLeaveCriticalSection_hook));
            THROW_IF_WIN32_ERROR(DetourAttach(L"kernel32.dll", "GetSystemTimeAsFileTime", &g_pfnGetSystemTimeAsFileTime, GetSystemTimeAsFileTime_hook));
            const auto win32err = DetourAttach(L"user32.dll", "NtUserFindWindowEx", &g_pfnNtUserFindWindowEx, NtUserFindWindowEx_hook);
            
            if ( FAILED_WIN32(win32err) ) {
              if ( win32err == ERROR_PROC_NOT_FOUND )
                THROW_IF_WIN32_ERROR(DetourAttach(L"win32u.dll", "NtUserFindWindowEx", &g_pfnNtUserFindWindowEx, NtUserFindWindowEx_hook));
              else
                THROW_WIN32(win32err);
            }
            THROW_IF_WIN32_ERROR(DetourTransactionCommit());
          }
          break;
        }
      }
    }
  }
  return TRUE;
}

const PfnDliHook __pfnDliNotifyHook2 = [](unsigned dliNotify, PDelayLoadInfo pdli) -> FARPROC {
  static INIT_ONCE once = INIT_ONCE_STATIC_INIT;

  switch ( dliNotify ) {
    case dliNotePreLoadLibrary: {
      std::wstring result;
      if ( SUCCEEDED(wil::GetSystemDirectoryW(result)) ) {
        std::filesystem::path path{std::move(result)};
        path /= pdli->szDll;
        return reinterpret_cast<FARPROC>(LoadLibraryExW(path.c_str(), nullptr, LOAD_WITH_ALTERED_SEARCH_PATH));
      }
      break;
    }
  }
  return nullptr;
};
