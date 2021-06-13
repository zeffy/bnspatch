#include "pch.h"
#include "globals.h"
#include "hooks.h"
#include "pluginsdk.h"

static inline void hide_from_peb(HMODULE hLibModule)
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

decltype(&RtlLeaveCriticalSection) g_pfnRtlLeaveCriticalSection;
NTSTATUS NTAPI RtlLeaveCriticalSection_hook(PRTL_CRITICAL_SECTION CriticalSection)
{
  static std::atomic_flag flag;

  const auto Status = g_pfnRtlLeaveCriticalSection(CriticalSection);

  if ( NT_SUCCESS(Status)
    && CriticalSection == NtCurrentPeb()->LoaderLock
    && CriticalSection->OwningThread == nullptr
    && !flag.test_and_set() ) {

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

      const auto ext = entry.path().extension();
      if ( _wcsicmp(ext.c_str(), L".dll") != 0 )
        continue;

      wil::unique_hmodule hlib{LoadLibraryExW(entry.path().c_str(), nullptr, LOAD_WITH_ALTERED_SEARCH_PATH)};
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
  return Status;
}

decltype(&GetSystemTimeAsFileTime) g_pfnGetSystemTimeAsFileTime;
VOID WINAPI GetSystemTimeAsFileTime_hook(LPFILETIME lpSystemTimeAsFileTime)
{
  static INIT_ONCE InitOnce = INIT_ONCE_STATIC_INIT;

  PVOID buffer[16];
  std::span callers{buffer, static_cast<size_t>(RtlWalkFrameChain(buffer, ARRAYSIZE(buffer), 0))};
  InitOnceExecuteOnce(&InitOnce, [](PINIT_ONCE InitOnce, PVOID Parameter, PVOID *Context) -> BOOL {
    const auto callers = reinterpret_cast<std::span<PVOID> *>(Parameter);
    MEMORY_BASIC_INFORMATION mbi;
    const auto it = std::find_if(callers->begin(), callers->end(), [&](PVOID caller) {
      return VirtualQuery(caller, &mbi, sizeof(MEMORY_BASIC_INFORMATION)) != 0
        && (mbi.State == MEM_COMMIT && (mbi.Protect & 0xff) != PAGE_NOACCESS && (mbi.Protect & PAGE_GUARD) == 0)
        && mbi.AllocationBase != wil::GetModuleInstanceHandle();
    });
    if ( it != callers->end() && mbi.AllocationBase == NtCurrentPeb()->ImageBaseAddress ) {
      for ( const auto &[hlib, plugin_info] : GPlugins ) {
        if ( plugin_info->oep_notify )
          plugin_info->oep_notify(GClientVersion);
      }
      return TRUE;
    }
    return FALSE;
  }, &callers, nullptr);
  return g_pfnGetSystemTimeAsFileTime(lpSystemTimeAsFileTime);
}
