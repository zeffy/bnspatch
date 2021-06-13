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
      if ( !resInfo ) break;

      const auto count = SizeofResource(nullptr, resInfo);
      if ( !count ) break;

      const auto ptr = LoadResource(nullptr, resInfo);
      if ( !ptr ) break;

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
        for ( const auto &t : std::span{static_cast<LANGANDCODEPAGE *>(buffer), static_cast<size_t>(len) / sizeof(LANGANDCODEPAGE)} ) {
          const auto subBlock = fmt::format(FMT_COMPILE(L"\\StringFileInfo\\{:04x}{:04x}\\OriginalFilename"), t.wLanguage, t.wCodePage);

          if ( !VerQueryValueW(block.data(), subBlock.c_str(), &buffer, &len) )
            continue;

          const std::wstring_view originalFilename{static_cast<LPCWSTR>(buffer), len - 1};
          if ( originalFilename == L"Client.exe"sv || originalFilename == L"BNSR.exe"sv ) {
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
            THROW_IF_WIN32_ERROR(DetourAttach(L"ntdll.dll", "RtlLeaveCriticalSection", &g_pfnRtlLeaveCriticalSection, RtlLeaveCriticalSection_hook));
            THROW_IF_WIN32_ERROR(DetourAttach(L"kernel32.dll", "GetSystemTimeAsFileTime", &g_pfnGetSystemTimeAsFileTime, GetSystemTimeAsFileTime_hook));
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
