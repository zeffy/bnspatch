#include "pch.h"
#include <delayimp.h>
#include "globals.h"
#include "hooks.h"
#include "pluginsdk.h"

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
  switch ( ul_reason_for_call ) {
    case DLL_PROCESS_ATTACH: {
      if ( hModule != wil::GetModuleInstanceHandle() )
        (VOID)SHCreateProcessAsUserW(nullptr); // stupid hack to ensure shell32.dll is loaded

      const auto resInfo = FindResourceW(nullptr, MAKEINTRESOURCEW(VS_VERSION_INFO), VS_FILE_INFO);
      if ( !resInfo ) return TRUE;

      const auto count = SizeofResource(nullptr, resInfo);
      if ( !count ) return TRUE;

      const auto ptr = LoadResource(nullptr, resInfo);
      if ( !ptr ) return TRUE;

      const std::span res{reinterpret_cast<PUCHAR>(ptr), count};
      const std::vector<UCHAR> block{res.begin(), res.end()};

      LPVOID buffer;
      UINT len;
      if ( VerQueryValueW(block.data(), L"\\VarFileInfo\\Translation", &buffer, &len) ) {
        for ( const auto &t : std::span{(PLANGANDCODEPAGE)buffer, len / sizeof(LANGANDCODEPAGE)} ) {
          const auto subBlock = std::format(L"\\StringFileInfo\\{:04x}{:04x}\\OriginalFilename", t.wLanguage, t.wCodePage);

          if ( !VerQueryValueW(block.data(), subBlock.c_str(), &buffer, &len) )
            continue;

          const std::wstring_view originalFilename{static_cast<LPCWSTR>(buffer), len - 1};
          if ( originalFilename == L"Client.exe"sv || originalFilename == L"BNSR.exe"sv ) {
            NtCurrentPeb()->BeingDebugged = FALSE;

            if ( VerQueryValueW(block.data(), L"\\", &buffer, &len) && len == sizeof(VS_FIXEDFILEINFO) ) {
              const auto vsf = static_cast<VS_FIXEDFILEINFO *>(buffer);
              GClientVersion.major = HIWORD(vsf->dwProductVersionMS);
              GClientVersion.minor = LOWORD(vsf->dwProductVersionMS);
              GClientVersion.build = HIWORD(vsf->dwProductVersionLS);
              GClientVersion.revision = LOWORD(vsf->dwProductVersionLS);
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
            g_pfnNtQueryInformationProcess = reinterpret_cast<decltype(&NtQueryInformationProcess)>(GetProcAddress(hNtDll, "NtQueryInformationProcess"));
            THROW_LAST_ERROR_IF_NULL(g_pfnNtQueryInformationProcess);
#ifdef _WIN64
            THROW_IF_WIN32_ERROR(DetourAttach(&(PVOID &)g_pfnNtQueryInformationProcess, NtQueryInformationProcess_hook));
#endif
            THROW_IF_WIN32_ERROR(DetourAttach(hNtDll, "NtQuerySystemInformation", &g_pfnNtQuerySystemInformation, NtQuerySystemInformation_hook));
            g_pfnNtSetInformationThread = reinterpret_cast<decltype(&NtSetInformationThread)>(GetProcAddress(hNtDll, "NtSetInformationThread"));
            THROW_LAST_ERROR_IF_NULL(g_pfnNtSetInformationThread);
#ifdef _WIN64
            THROW_IF_WIN32_ERROR(DetourAttach(&(PVOID &)g_pfnNtSetInformationThread, NtSetInformationThread_hook));
#endif
            THROW_IF_WIN32_ERROR(DetourAttach(L"kernel32.dll", "GetSystemTimeAsFileTime", &g_pfnGetSystemTimeAsFileTime, GetSystemTimeAsFileTime_hook));
            THROW_IF_WIN32_ERROR(DetourAttach(L"shell32.dll", "SHTestTokenMembership", &g_pfnSHTestTokenMembership, SHTestTokenMembership_hook));
            THROW_IF_WIN32_ERROR(DetourAttach(L"user32.dll", "FindWindowA", &g_pfnFindWindowA, FindWindowA_hook));
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
      THROW_IF_NTSTATUS_FAILED(wil::GetSystemDirectoryW(result));

      std::filesystem::path path{std::move(result)};
      path /= pdli->szDll;
      return reinterpret_cast<FARPROC>(LoadLibraryExW(path.c_str(), nullptr, LOAD_WITH_ALTERED_SEARCH_PATH));
      break;
    }
  }
  return nullptr;
};
