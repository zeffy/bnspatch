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
      const std::vector block{res};

      struct LANGANDCODEPAGE
      {
        WORD wLanguage;
        WORD wCodePage;
      };

      LPVOID buffer;
      UINT len;
      if ( VerQueryValueW(block.data(), L"\\", &buffer, &len) && len == sizeof(VS_FIXEDFILEINFO) ) {
        const auto vsf = static_cast<VS_FIXEDFILEINFO *>(buffer);
        GClientVersion = (static_cast<uint64_t>(vsf->dwProductVersionMS) << 32) | vsf->dwProductVersionLS;
      }
      if ( VerQueryValueW(block.data(), L"\\VarFileInfo\\Translation", &buffer, &len) ) {
        for ( const auto &t : std::span{static_cast<LANGANDCODEPAGE *>(buffer), static_cast<size_t>(len) / sizeof(LANGANDCODEPAGE)} ) {
          const auto subBlock = fmt::format(FMT_COMPILE(L"\\StringFileInfo\\{:04x}{:04x}\\OriginalFilename"), t.wLanguage, t.wCodePage);

          if ( !VerQueryValueW(block.data(), subBlock.c_str(), &buffer, &len) )
            continue;

          const std::wstring_view originalFilename{static_cast<LPCWSTR>(buffer), len - 1};
          if ( originalFilename != L"Client.exe"sv && originalFilename != L"BNSR.exe"sv ) {
            wil::unique_handle tokenHandle;
            THROW_IF_WIN32_BOOL_FALSE(OpenProcessToken(NtCurrentProcess(), TOKEN_WRITE, &tokenHandle));
            ULONG virtualizationEnabled = TRUE;
            THROW_IF_WIN32_BOOL_FALSE(SetTokenInformation(tokenHandle.get(), TokenVirtualizationEnabled, &virtualizationEnabled, sizeof(ULONG)));

            THROW_IF_WIN32_ERROR(DetourTransactionBegin());
            THROW_IF_WIN32_ERROR(DetourUpdateThread(NtCurrentThread()));
            THROW_IF_WIN32_ERROR(DetourAttach(L"kernel32.dll", "GetPrivateProfileStringW", &g_pfnGetPrivateProfileStringW, GetPrivateProfileStringW_hook));
            THROW_IF_WIN32_ERROR(DetourTransactionCommit());
          }
          break;
        }
      }
    }
  }
  return TRUE;
}

inline void hide_from_peb(HMODULE hLibModule)
{
  const auto cs = static_cast<nt::rtl::critical_section *>(NtCurrentPeb()->LoaderLock);
  std::lock_guard<nt::rtl::critical_section> guard(*cs);

  const auto ldrData = NtCurrentPeb()->Ldr;

  for ( auto Next = ldrData->InLoadOrderModuleList.Flink; Next != &ldrData->InLoadOrderModuleList; Next = Next->Flink ) {
    const auto Entry = CONTAINING_RECORD(Next, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
    if ( Entry->DllBase == hLibModule ) {
      RemoveEntryList(Next);
      break;
    }
  }
  for ( auto Next = ldrData->InMemoryOrderModuleList.Flink; Next != &ldrData->InMemoryOrderModuleList; Next = Next->Flink ) {
    const auto Entry = CONTAINING_RECORD(Next, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
    if ( Entry->DllBase == hLibModule ) {
      RemoveEntryList(Next);
      break;
    }
  }
  for ( auto Next = ldrData->InInitializationOrderModuleList.Flink; Next != &ldrData->InInitializationOrderModuleList; Next = Next->Flink ) {
    const auto Entry = CONTAINING_RECORD(Next, LDR_DATA_TABLE_ENTRY, InInitializationOrderLinks);
    if ( Entry->DllBase == hLibModule ) {
      RemoveEntryList(Next);
      break;
    }
  }
}

void loader3_once_fx(LPCSTR pszDll)
{
  const auto Base = wil::GetModuleInstanceHandle();
  const auto ExportDir = nt::rtl::image_directory_entry_to_data<IMAGE_EXPORT_DIRECTORY>(Base, IMAGE_DIRECTORY_ENTRY_EXPORT);
  if ( !ExportDir )
    return;

  const auto ModuleName = nt::rtl::image_rva_to_va<CHAR>(Base, ExportDir->Name);
  if ( !ModuleName || _stricmp(ModuleName, pszDll) != 0 )
    return;

  std::filesystem::path application_dir{std::move(wil::GetModuleFileNameW<std::wstring>(nullptr))};
  application_dir.remove_filename();

  std::filesystem::path path;
  if ( const auto str = wil::TryGetEnvironmentVariableW(L"BNS_PROFILE_PLUGINS_DIR") ) {
    THROW_IF_WIN32_BOOL_FALSE(SetEnvironmentVariableW(L"BNS_PROFILE_PLUGINS_DIR", nullptr));
    std::filesystem::path tmp{wil::str_raw_ptr(str)};
    if ( tmp.is_relative() )
      path = application_dir / tmp;
    else
      path = std::move(tmp);
  } else {
    path = application_dir / L"plugins";
  }

  std::error_code ec;
  for ( const auto &entry : std::filesystem::directory_iterator{path, ec} ) {
    if ( !entry.is_regular_file() )
      continue;

    const auto &filename = entry.path();
    const auto ext = filename.extension().wstring();
    if ( CompareStringOrdinal(ext.c_str(), static_cast<int>(ext.size()), L".dll", -1, TRUE) != CSTR_EQUAL )
      continue;

    wil::unique_hmodule hlib{LoadLibraryExW(filename.c_str(), nullptr, LOAD_WITH_ALTERED_SEARCH_PATH)};
    if ( hlib ) {
      const auto plugin_info = reinterpret_cast<const plugin_info_t *>(GetProcAddress(hlib.get(), "GPluginInfo"));
      if ( !plugin_info )
        continue;

      if ( plugin_info->sdk_version == PLUGIN_SDK_VERSION )
        GPlugins.emplace_back(std::move(hlib), plugin_info);
    }
  }
  std::stable_sort(GPlugins.begin(), GPlugins.end(), [](const auto &lhs, const auto &rhs) {
    return lhs.second->priority > rhs.second->priority;
  });
  GPlugins.remove_if([](const auto &entry) {
    return entry.second->init && !entry.second->init(GClientVersion);
  });
  for ( const auto &[hlib, plugin_info] : GPlugins ) {
    if ( plugin_info->hide_from_peb )
      hide_from_peb(hlib.get());

    if ( plugin_info->erase_pe_header ) {
      const auto nt_headers = nt::rtl::image_nt_headers(hlib.get());
      const nt::rtl::protect_memory protect{hlib.get(), nt_headers->OptionalHeader.SizeOfHeaders, PAGE_READWRITE};
      SecureZeroMemory(hlib.get(), nt_headers->OptionalHeader.SizeOfHeaders);
    }
  }
}

const PfnDliHook __pfnDliNotifyHook2 = [](unsigned dliNotify, PDelayLoadInfo pdli) -> FARPROC {
  switch ( dliNotify ) {
    case dliNotePreLoadLibrary: {
      static std::once_flag once;
      std::call_once(once, loader3_once_fx, pdli->szDll);

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
