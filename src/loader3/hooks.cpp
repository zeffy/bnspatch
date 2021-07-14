#include "pch.h"
#include "globals.h"
#include "hooks.h"
#include "pluginsdk.h"
#include "vendor.h"
#include "thread_local_mutex.h"
#include "FastWildCompare.hpp"
#include "wl.h"

static UNICODE_STRING Util_GetFileName(const UNICODE_STRING &FullName)
{
  auto Name = FullName;
  auto It = rtl::rbegin(FullName);
  for ( ; It != rtl::rend(FullName); ++It ) {
    if ( *It == '\\' || *It == '/' ) {
      const safe_ptrdiff_t length = std::distance(rtl::rbegin(FullName), It) * sizeof(WCHAR);
      --It;
      Name.Buffer = const_cast<PWCH>(&*It);
      Name.Length = length;
      Name.MaximumLength = length;
      break;
    }
  }
  return Name;
}

decltype(&LdrGetDllHandle) g_pfnLdrGetDllHandle;
NTSTATUS NTAPI LdrGetDllHandle_hook(
  _In_opt_ PWSTR DllPath,
  _In_opt_ PULONG DllCharacteristics,
  _In_ PUNICODE_STRING DllName,
  _Out_ PVOID *DllHandle)
{
  const auto Name = Util_GetFileName(*DllName);
  if (
#ifndef _WIN64
    rtl::iequals(Name, L"kmon.dll") ||
#endif
    rtl::iequals(Name, L"dateinj01.dll")
    ) {
    DllHandle = nullptr;
    return STATUS_DLL_NOT_FOUND;
  }
  return g_pfnLdrGetDllHandle(DllPath, DllCharacteristics, DllName, DllHandle);
}

decltype(&LdrLoadDll) g_pfnLdrLoadDll;
NTSTATUS NTAPI LdrLoadDll_hook(
  _In_opt_ PWSTR DllPath,
  _In_opt_ PULONG DllCharacteristics,
  _In_ PUNICODE_STRING DllName,
  _Out_ PVOID *DllHandle)
{
  const auto Name = Util_GetFileName(*DllName);
  if ( rtl::istarts_with(Name, L"aegisty")
    || rtl::iequals(Name, L"NCCrashReporter.dll")
    /*|| rtl::iequals(Name, L"BugTrace.dll")*/ ) {
    *DllHandle = nullptr;
    return STATUS_DLL_NOT_FOUND;
  }
  return g_pfnLdrLoadDll(DllPath, DllCharacteristics, DllName, DllHandle);
}

decltype(&NtCreateFile) g_pfnNtCreateFile;
NTSTATUS NTAPI NtCreateFile_hook(
  _Out_ PHANDLE FileHandle,
  _In_ ACCESS_MASK DesiredAccess,
  _In_ POBJECT_ATTRIBUTES ObjectAttributes,
  _Out_ PIO_STATUS_BLOCK IoStatusBlock,
  _In_opt_ PLARGE_INTEGER AllocationSize,
  _In_ ULONG FileAttributes,
  _In_ ULONG ShareAccess,
  _In_ ULONG CreateDisposition,
  _In_ ULONG CreateOptions,
  _In_reads_bytes_opt_(EaLength) PVOID EaBuffer,
  _In_ ULONG EaLength)
{
#if !defined(_WIN64)
  if ( WLIsProtected() ) {
    constexpr std::array ObjectNames{
      L"\\\\.\\SICE",
      L"\\\\.\\SIWVID",
      L"\\\\.\\NTICE",
    };
    if ( std::ranges::any_of(ObjectNames, [oa = ObjectAttributes](const auto p) { return rtl::iequals(*oa->ObjectName, p); }) )
      return STATUS_OBJECT_NAME_NOT_FOUND;
  }
#endif
  return g_pfnNtCreateFile(
    FileHandle,
    DesiredAccess,
    ObjectAttributes,
    IoStatusBlock,
    AllocationSize,
    FileAttributes,
    ShareAccess ? ShareAccess : FILE_SHARE_READ,
    CreateDisposition,
    CreateOptions,
    EaBuffer,
    EaLength);
}

decltype(&NtCreateMutant) g_pfnNtCreateMutant;
NTSTATUS NTAPI NtCreateMutant_hook(
  _Out_ PHANDLE MutantHandle,
  _In_ ACCESS_MASK DesiredAccess,
  _In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
  _In_ BOOLEAN InitialOwner)
{
  if ( ObjectAttributes
    && ObjectAttributes->ObjectName
    && rtl::istarts_with(*ObjectAttributes->ObjectName, L"BnSGameClient") ) {

    ObjectAttributes->ObjectName = nullptr;
    ObjectAttributes->Attributes &= ~OBJ_OPENIF;
    ObjectAttributes->RootDirectory = nullptr;
  }
  return g_pfnNtCreateMutant(MutantHandle, DesiredAccess, ObjectAttributes, InitialOwner);
}

decltype(&NtOpenKeyEx) g_pfnNtOpenKeyEx;
NTSTATUS NTAPI NtOpenKeyEx_hook(
  _Out_ PHANDLE KeyHandle,
  _In_ ACCESS_MASK DesiredAccess,
  _In_ POBJECT_ATTRIBUTES ObjectAttributes,
  _In_ ULONG OpenOptions)
{
  constexpr std::array ObjectNames{
    L"Software\\Wine",
    L"HARDWARE\\ACPI\\DSDT\\VBOX__"
  };
  if ( std::ranges::any_of(ObjectNames, [oa = ObjectAttributes](const auto p) { return rtl::iequals(*oa->ObjectName, p); }) )
    return STATUS_OBJECT_NAME_NOT_FOUND;
  return g_pfnNtOpenKeyEx(KeyHandle, DesiredAccess, ObjectAttributes, OpenOptions);
}

decltype(&NtProtectVirtualMemory) g_pfnNtProtectVirtualMemory;
NTSTATUS NTAPI NtProtectVirtualMemory_hook(
  _In_ HANDLE ProcessHandle,
  _Inout_ PVOID *BaseAddress,
  _Inout_ PSIZE_T RegionSize,
  _In_ ULONG NewProtect,
  _Out_ PULONG OldProtect)
{
  PROCESS_BASIC_INFORMATION ProcessInfo;
  SYSTEM_BASIC_INFORMATION SystemInfo;
  PVOID StartingAddress;

  if ( (NewProtect & PAGE_WRITE_ANY) != 0
    && (ProcessHandle == NtCurrentProcess()
      || (SUCCEEDED_NTSTATUS(g_pfnNtQueryInformationProcess(ProcessHandle, ProcessBasicInformation, &ProcessInfo, sizeof(PROCESS_BASIC_INFORMATION), nullptr))
        && ProcessInfo.UniqueProcessId == NtCurrentTeb()->ClientId.UniqueProcess))
    && SUCCEEDED_NTSTATUS(g_pfnNtQuerySystemInformation(SystemBasicInformation, &SystemInfo, sizeof(SYSTEM_BASIC_INFORMATION), nullptr)) ) {

    __try {
      StartingAddress = PAGE_ALIGN(*BaseAddress);
    } __except ( EXCEPTION_EXECUTE_HANDLER ) {
      return GetExceptionCode();
    }

    if ( StartingAddress == PAGE_ALIGN(&DbgBreakPoint)
      || StartingAddress == PAGE_ALIGN(&DbgUiRemoteBreakin) )
      return STATUS_INVALID_PARAMETER_2;
  }
  return g_pfnNtProtectVirtualMemory(ProcessHandle, BaseAddress, RegionSize, NewProtect, OldProtect);
}

decltype(&NtQueryInformationProcess) g_pfnNtQueryInformationProcess;
NTSTATUS NTAPI NtQueryInformationProcess_hook(
  _In_ HANDLE ProcessHandle,
  _In_ PROCESSINFOCLASS ProcessInformationClass,
  _Out_writes_bytes_(ProcessInformationLength) PVOID ProcessInformation,
  _In_ ULONG ProcessInformationLength,
  _Out_opt_ PULONG ReturnLength)
{
  PROCESS_BASIC_INFORMATION ProcessInfo;

  if ( ProcessHandle == NtCurrentProcess()
    || (SUCCEEDED_NTSTATUS(g_pfnNtQueryInformationProcess(ProcessHandle, ProcessBasicInformation, &ProcessInfo, sizeof(PROCESS_BASIC_INFORMATION), nullptr))
      && ProcessInfo.UniqueProcessId == NtCurrentTeb()->ClientId.UniqueProcess) ) {

    switch ( ProcessInformationClass ) {
      case ProcessDebugPort:
        if ( ProcessInformationLength != sizeof(DWORD_PTR) )
          return STATUS_INFO_LENGTH_MISMATCH;
        *(PDWORD_PTR)ProcessInformation = 0;
        if ( ReturnLength )
          *ReturnLength = sizeof(DWORD_PTR);
        return STATUS_SUCCESS;

      case ProcessDebugObjectHandle:
        if ( ProcessInformationLength != sizeof(HANDLE) )
          return STATUS_INFO_LENGTH_MISMATCH;
        *(PHANDLE)ProcessInformation = nullptr;
        if ( ReturnLength )
          *ReturnLength = sizeof(HANDLE);
        return STATUS_PORT_NOT_SET;
    }
  }
  return g_pfnNtQueryInformationProcess(ProcessHandle, ProcessInformationClass, ProcessInformation, ProcessInformationLength, ReturnLength);
}

decltype(&NtQuerySystemInformation) g_pfnNtQuerySystemInformation;
NTSTATUS NTAPI NtQuerySystemInformation_hook(
  SYSTEM_INFORMATION_CLASS SystemInformationClass,
  PVOID SystemInformation,
  ULONG SystemInformationLength,
  PULONG ReturnLength)
{
  switch ( SystemInformationClass ) {
    case SystemSessionProcessInformation:
    case SystemProcessInformation:
    case SystemExtendedProcessInformation:
    case SystemFullProcessInformation:
    {
      ULONG MyReturnLength;
      const auto Status = g_pfnNtQuerySystemInformation(SystemInformationClass, SystemInformation, SystemInformationLength, &MyReturnLength);
      if ( SUCCEEDED_NTSTATUS(Status) ) {
        PSYSTEM_PROCESS_INFORMATION Start;
        ULONG SizeOfBuf;
        if ( SystemInformationClass == SystemSessionProcessInformation ) {
          Start = (PSYSTEM_PROCESS_INFORMATION)((PSYSTEM_SESSION_PROCESS_INFORMATION)SystemInformation)->Buffer;
          SizeOfBuf = ((PSYSTEM_SESSION_PROCESS_INFORMATION)SystemInformation)->SizeOfBuf;
        } else {
          Start = (PSYSTEM_PROCESS_INFORMATION)SystemInformation;
          SizeOfBuf = MyReturnLength;
        }
        if ( Start->NextEntryOffset ) {
          PSYSTEM_PROCESS_INFORMATION Entry = Start;
          PSYSTEM_PROCESS_INFORMATION PreviousEntry = nullptr;
          ULONG NextEntryOffset;

          const auto Name = Util_GetFileName(NtCurrentPeb()->ProcessParameters->ImagePathName);
          do {
            PreviousEntry = Entry;
            Entry = (PSYSTEM_PROCESS_INFORMATION)((PUCHAR)PreviousEntry + PreviousEntry->NextEntryOffset);
            NextEntryOffset = Entry->NextEntryOffset;
            const auto EntrySize = NextEntryOffset ? NextEntryOffset : SizeOfBuf - (ULONG)((PUCHAR)Entry - (PUCHAR)Start);
            CLIENT_ID ClientId{Entry->UniqueProcessId, 0};
            OBJECT_ATTRIBUTES ObjectAttributes;
            InitializeObjectAttributes(&ObjectAttributes, nullptr, 0, nullptr, nullptr);
            HANDLE ProcessHandle;
            if ( SUCCEEDED_NTSTATUS(NtOpenProcess(&ProcessHandle, PROCESS_QUERY_LIMITED_INFORMATION, &ObjectAttributes, &ClientId)) ) {
              auto MyStatus = g_pfnNtQueryInformationProcess(ProcessHandle, ProcessImageFileNameWin32, nullptr, 0, &MyReturnLength);
              if ( FAILED_NTSTATUS(MyStatus) && MyStatus != STATUS_INFO_LENGTH_MISMATCH )
                continue;
              PUNICODE_STRING Buffer = nullptr;
              do {
                if ( Buffer )
                  (VOID)RtlFreeHeap(RtlProcessHeap(), 0, Buffer);
                Buffer = (PUNICODE_STRING)RtlAllocateHeap(RtlProcessHeap(), HEAP_ZERO_MEMORY, MyReturnLength);
                if ( !Buffer )
                  return STATUS_INSUFFICIENT_RESOURCES;
                MyStatus = g_pfnNtQueryInformationProcess(ProcessHandle, ProcessImageFileNameWin32, Buffer, MyReturnLength, &MyReturnLength);
              } while ( MyStatus == STATUS_INFO_LENGTH_MISMATCH );
              if ( SUCCEEDED_NTSTATUS(MyStatus) ) {
                if ( Entry->UniqueProcessId != NtCurrentTeb()->ClientId.UniqueProcess
                  && (rtl::iequals(Name, Entry->ImageName) || !IsVendorModule(Buffer)) ) {
                  RtlSecureZeroMemory(Entry, EntrySize);
                  PreviousEntry->NextEntryOffset += NextEntryOffset;
                  Entry = PreviousEntry;
                }
                (VOID)RtlFreeHeap(RtlProcessHeap(), 0, Buffer);
              }
              (VOID)NtClose(ProcessHandle);
            }
          } while ( NextEntryOffset );
        }
      }
      __try {
        if ( ReturnLength )
          *ReturnLength = MyReturnLength;
      } __except ( EXCEPTION_EXECUTE_HANDLER ) {
        return GetExceptionCode();
      }
      return Status;
    }
  }
  if ( WLIsProtected() ) {
    switch ( SystemInformationClass ) {
      case SystemModuleInformation:
        if ( SystemInformationLength < FIELD_OFFSET(RTL_PROCESS_MODULES, Modules) )
          return STATUS_INFO_LENGTH_MISMATCH;
        return STATUS_ACCESS_DENIED;

      case SystemModuleInformationEx:
        if ( SystemInformationLength < sizeof(RTL_PROCESS_MODULE_INFORMATION_EX) )
          return STATUS_INFO_LENGTH_MISMATCH;
        return STATUS_ACCESS_DENIED;

      case SystemKernelDebuggerInformation:
        if ( SystemInformationLength < sizeof(SYSTEM_KERNEL_DEBUGGER_INFORMATION) )
          return STATUS_INFO_LENGTH_MISMATCH;
        ((PSYSTEM_KERNEL_DEBUGGER_INFORMATION)SystemInformation)->KernelDebuggerEnabled = FALSE;
        ((PSYSTEM_KERNEL_DEBUGGER_INFORMATION)SystemInformation)->KernelDebuggerNotPresent = TRUE;
        __try {
          if ( ReturnLength )
            *ReturnLength = sizeof(SYSTEM_KERNEL_DEBUGGER_INFORMATION);
        } __except ( EXCEPTION_EXECUTE_HANDLER ) {
          return GetExceptionCode();
        }
        return STATUS_SUCCESS;
    }
  }
  return g_pfnNtQuerySystemInformation(
    SystemInformationClass,
    SystemInformation,
    SystemInformationLength,
    ReturnLength);
}

decltype(&NtSetInformationThread) g_pfnNtSetInformationThread;
NTSTATUS NTAPI NtSetInformationThread_hook(
  _In_ HANDLE ThreadHandle,
  _In_ THREADINFOCLASS ThreadInformationClass,
  _In_reads_bytes_(ThreadInformationLength) PVOID ThreadInformation,
  _In_ ULONG ThreadInformationLength)
{
  THREAD_BASIC_INFORMATION ThreadInfo;

  if ( ThreadInformationClass == ThreadHideFromDebugger ) {
    if ( ThreadInformationLength != 0 )
      return STATUS_INFO_LENGTH_MISMATCH;

    if ( ThreadHandle == NtCurrentThread()
      || (SUCCEEDED_NTSTATUS(NtQueryInformationThread(ThreadHandle, ThreadBasicInformation, &ThreadInfo, sizeof(THREAD_BASIC_INFORMATION), 0))
        && ThreadInfo.ClientId.UniqueProcess == NtCurrentTeb()->ClientId.UniqueProcess) )
      return STATUS_SUCCESS;
  }
  return g_pfnNtSetInformationThread(ThreadHandle, ThreadInformationClass, ThreadInformation, ThreadInformationLength);
}

decltype(&NtGetContextThread) g_pfnNtGetContextThread;
NTSTATUS NTAPI NtGetContextThread_hook(
  _In_ HANDLE ThreadHandle,
  _Inout_ PCONTEXT ThreadContext)
{
  THREAD_BASIC_INFORMATION ThreadInfo;
  DWORD ContextFlags = 0;

  if ( ThreadHandle == NtCurrentThread()
    || (SUCCEEDED_NTSTATUS(NtQueryInformationThread(ThreadHandle, ThreadBasicInformation, &ThreadInfo, sizeof(THREAD_BASIC_INFORMATION), 0))
      && ThreadInfo.ClientId.UniqueProcess == NtCurrentTeb()->ClientId.UniqueProcess) ) {

    __try {
      ContextFlags = ThreadContext->ContextFlags;
      ThreadContext->ContextFlags &= ~CONTEXT_DEBUG_REGISTERS;
    } __except ( EXCEPTION_EXECUTE_HANDLER ) {
      return GetExceptionCode();
    }
  }

  const auto status = g_pfnNtGetContextThread(ThreadHandle, ThreadContext);
  if ( FAILED_NTSTATUS(status) )
    return status;

  ThreadContext->ContextFlags = ContextFlags;
  if ( (ContextFlags & CONTEXT_DEBUG_REGISTERS) == CONTEXT_DEBUG_REGISTERS ) {
    ThreadContext->Dr0 = 0;
    ThreadContext->Dr1 = 0;
    ThreadContext->Dr2 = 0;
    ThreadContext->Dr3 = 0;
    ThreadContext->Dr6 = 0;
    ThreadContext->Dr7 = 0;
#ifdef _WIN64
    ThreadContext->LastBranchToRip = 0;
    ThreadContext->LastBranchFromRip = 0;
    ThreadContext->LastExceptionToRip = 0;
    ThreadContext->LastExceptionFromRip = 0;
#endif
  }
  return status;
}

decltype(&NtCreateThreadEx) g_pfnNtCreateThreadEx;
NTSTATUS NTAPI NtCreateThreadEx_hook(
  _Out_ PHANDLE ThreadHandle,
  _In_ ACCESS_MASK DesiredAccess,
  _In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
  _In_ HANDLE ProcessHandle,
  _In_ PVOID StartRoutine, // PUSER_THREAD_START_ROUTINE
  _In_opt_ PVOID Argument,
  _In_ ULONG CreateFlags, // THREAD_CREATE_FLAGS_*
  _In_ SIZE_T ZeroBits,
  _In_ SIZE_T StackSize,
  _In_ SIZE_T MaximumStackSize,
  _In_opt_ PPS_ATTRIBUTE_LIST AttributeList)
{
  PROCESS_BASIC_INFORMATION ProcessInfo;

  if ( ProcessHandle == NtCurrentProcess()
    || (SUCCEEDED_NTSTATUS(g_pfnNtQueryInformationProcess(ProcessHandle, ProcessBasicInformation, &ProcessInfo, sizeof(PROCESS_BASIC_INFORMATION), nullptr))
      && ProcessInfo.UniqueProcessId == NtCurrentTeb()->ClientId.UniqueProcess) ) {

    const auto Entry = rtl::pc_to_ldr_data_table_entry(StartRoutine);
    if ( Entry && Entry->DllBase == NtCurrentPeb()->ImageBaseAddress ) {
      const auto Sections = rtl::image_sections(Entry->DllBase);
      const auto Section = rtl::find_image_section_by_name(Sections, ".winlice");
      if ( Section != Sections.end() ) {
        const auto Start = rtl::image_rva_to_va<uchar>(Entry->DllBase, Section->VirtualAddress);
        const auto End = Start + Section->Misc.VirtualSize;
        if ( StartRoutine >= Start && StartRoutine < End ) {
          const auto text = std::format(L"[loader3] Refusing thread creation at entry {:.{}}+{:#x}.\n",
            Entry->BaseDllName.Buffer,
            Entry->BaseDllName.Length >> 1,
            (ULONG_PTR)StartRoutine - (ULONG_PTR)Entry->DllBase);
          OutputDebugStringW(text.c_str());
          return STATUS_INSUFFICIENT_RESOURCES;
        }
      }
    }
    CreateFlags &= ~THREAD_CREATE_FLAGS_HIDE_FROM_DEBUGGER;
  }
  return g_pfnNtCreateThreadEx(
    ThreadHandle,
    DesiredAccess,
    ObjectAttributes,
    ProcessHandle,
    StartRoutine,
    Argument,
    CreateFlags,
    ZeroBits,
    StackSize,
    MaximumStackSize,
    AttributeList);
}

static inline void hide_from_peb(HMODULE hLibModule)
{
  const std::unique_lock<rtl::loader_lock> lock;
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

decltype(&FindWindowA) g_pfnFindWindowA;
HWND WINAPI FindWindowA_hook(
  _In_opt_ LPCSTR lpClassName,
  _In_opt_ LPCSTR lpWindowName)
{
  constexpr std::array ClassNames{
#ifndef _WIN64
    "OLLYDBG",
    "GBDYLLO",
    "pediy06",
#endif         
    "FilemonClass",
    "PROCMON_WINDOW_CLASS",
    "RegmonClass",
    "18467-41"
  };
  if ( lpClassName && std::ranges::any_of(ClassNames, std::not_fn(std::bind_front(_stricmp, lpClassName))) )
    return nullptr;

  if ( lpWindowName ) {
    switch ( muu::fnv1a{}(lpWindowName).value() ) {
      case "File Monitor - Sysinternals: www.sysinternals.com"_fnv1a:
      case "Process Monitor - Sysinternals: www.sysinternals.com"_fnv1a:
      case "Registry Monitor - Sysinternals: www.sysinternals.com"_fnv1a:
        return nullptr;
    }
  }
  return g_pfnFindWindowA(lpClassName, lpWindowName);
}

HRESULT Init()
{
  const auto resInfo = FindResourceW(nullptr, MAKEINTRESOURCEW(VS_VERSION_INFO), VS_FILE_INFO);
  if ( !resInfo ) return S_OK;

  const auto count = SizeofResource(nullptr, resInfo);
  if ( !count ) return S_OK;

  const auto ptr = LoadResource(nullptr, resInfo);
  if ( !ptr ) return S_OK;

  const std::span res{reinterpret_cast<PUCHAR>(ptr), count};
  const std::vector<UCHAR> block{res.begin(), res.end()};
  std::optional<std::wstring> ofilename;
  LPVOID buffer;
  UINT len;
  
  if ( VerQueryValueW(block.data(), L"\\", &buffer, &len) && len == sizeof(VS_FIXEDFILEINFO) ) {
    const auto vsf = static_cast<VS_FIXEDFILEINFO *>(buffer);
    GVersion.major = HIWORD(vsf->dwProductVersionMS);
    GVersion.minor = LOWORD(vsf->dwProductVersionMS);
    GVersion.build = HIWORD(vsf->dwProductVersionLS);
    GVersion.revision = LOWORD(vsf->dwProductVersionLS);
  }
  if ( VerQueryValueW(block.data(), L"\\VarFileInfo\\Translation", &buffer, &len) ) {
    for ( const auto &t : std::span{(PLANGANDCODEPAGE)buffer, len / sizeof(LANGANDCODEPAGE)} ) {
      auto subBlock = std::format(L"\\StringFileInfo\\{:04x}{:04x}\\OriginalFilename", t.wLanguage, t.wCodePage);
      if ( VerQueryValueW(block.data(), subBlock.c_str(), &buffer, &len) ) {
        ofilename.emplace(std::wstring_view{(LPWSTR)buffer, len - 1});
        break;
      }
    }
  }

  std::filesystem::path path{std::move(wil::GetModuleFileNameW<std::wstring>(nullptr))};
  const auto filename = path.filename();
  path.remove_filename();

  const auto str = wil::TryGetEnvironmentVariableW(L"BNS_PROFILE_PLUGINS_DIR");
  if ( str ) {
    THROW_IF_WIN32_BOOL_FALSE(SetEnvironmentVariableW(L"BNS_PROFILE_PLUGINS_DIR", nullptr));
    std::filesystem::path tmp{wil::str_raw_ptr(str)};
    if ( tmp.is_relative() )
      path /= tmp;
    else
      path = std::move(tmp);
  } else {
    path /= L"plugins"s;
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
      const auto info = reinterpret_cast<const PluginInfo *>(GetProcAddress(hlib.get(), "GPluginInfo")); // allow both
      if ( info && info->sdk_version >= 3 ) {
        std::wstring targetApps{info->sdk_version >= Version{3, 1} && info->target_apps ? info->target_apps : L"Client.exe"};
        wchar_t *context;
        auto token = wcstok_s(targetApps.data(), L";", &context);
        while ( token ) {
          if ( (ofilename && FastWildCompareW(ofilename->c_str(), token))
            || FastWildCompareW(filename.c_str(), token) ) {
            GPlugins.emplace_back(std::move(hlib), info, entry.path());
            break;
          }
          token = wcstok_s(nullptr, L";", &context);
        }
      }
    }
  }
  GPlugins.sort([](const auto &lhs, const auto &rhs) {
    return lhs.info->priority > rhs.info->priority;
  });
  std::erase_if(GPlugins, [](const auto &item) {
    return item.info->init && !item.info->init(GVersion);
  });
  for ( const auto &item : GPlugins ) {
    if ( item.info->hide_from_peb )
      hide_from_peb(item.hmodule.get());

    if ( item.info->erase_pe_header ) {
      const auto nt_headers = rtl::image_nt_headers(item.hmodule.get());
      const nt::rtl::protect_memory protect{item.hmodule.get(), nt_headers->OptionalHeader.SizeOfHeaders, PAGE_READWRITE};
      SecureZeroMemory(item.hmodule.get(), nt_headers->OptionalHeader.SizeOfHeaders);
    }
    const auto text = std::format(L"[loader3] Loaded plugin: \"{}\" ({:#x})", item.path.c_str(), reinterpret_cast<uintptr_t>(item.hmodule.get()));
    OutputDebugStringW(text.c_str());
  }
  return S_OK;
}

decltype(&GetSystemTimeAsFileTime) g_pfnGetSystemTimeAsFileTime;
VOID WINAPI GetSystemTimeAsFileTime_hook(LPFILETIME lpSystemTimeAsFileTime)
{
  static INIT_ONCE InitOnce = INIT_ONCE_STATIC_INIT;
  static thread_local_mutex mtx;
  const std::unique_lock lock{mtx, std::try_to_lock};

  if ( lock.owns_lock() ) {
    std::array<PVOID, 64> Buffer;
    const auto Count = RtlWalkFrameChain(Buffer.data(), SafeInt{Buffer.size()}, 0);
    const std::span<PVOID> Callers{Buffer.data(), Count};
    wil::init_once_nothrow(InitOnce, [&Callers]() {
      MEMORY_BASIC_INFORMATION mbi;

      const auto it = std::ranges::find_if(Callers, [&](PVOID Caller) {
        return VirtualQuery(Caller, &mbi, sizeof(MEMORY_BASIC_INFORMATION)) != 0
          && (mbi.State == MEM_COMMIT && (mbi.Protect & 0xff) != PAGE_NOACCESS && (mbi.Protect & PAGE_GUARD) == 0)
          && mbi.AllocationBase != wil::GetModuleInstanceHandle();
      });
      if ( it == Callers.end() || mbi.AllocationBase != NtCurrentPeb()->ImageBaseAddress )
        return E_FAIL;

      RETURN_IF_FAILED(Init());

      for ( const auto &item : GPlugins ) {
        if ( item.info->oep_notify )
          item.info->oep_notify(GVersion);
      }
      return S_OK;
    });
  }
  return g_pfnGetSystemTimeAsFileTime(lpSystemTimeAsFileTime);
}
