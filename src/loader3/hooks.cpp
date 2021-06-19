#include "pch.h"
#include "globals.h"
#include "hooks.h"
#include "pluginsdk.h"
#include "vendor.h"

decltype(&LdrGetDllHandle) g_pfnLdrGetDllHandle;
NTSTATUS NTAPI LdrGetDllHandle_hook(
  PWSTR DllPath,
  PULONG DllCharacteristics,
  PUNICODE_STRING DllName,
  PVOID *DllHandle)
{
  const auto Name = static_cast<nt::rtl::unicode_string_view *>(DllName);
  if (
#ifndef _WIN64
    Name->iequals(L"kmon.dll") ||
#endif
    Name->iequals(L"dateinj01.dll")
    ) {
    DllHandle = nullptr;
    return STATUS_DLL_NOT_FOUND;
  }
  return g_pfnLdrGetDllHandle(DllPath, DllCharacteristics, DllName, DllHandle);
}

decltype(&LdrLoadDll) g_pfnLdrLoadDll;
NTSTATUS NTAPI LdrLoadDll_hook(
  PWSTR DllPath,
  PULONG DllCharacteristics,
  PUNICODE_STRING DllName,
  PVOID *DllHandle)
{
  const auto FullName = static_cast<nt::rtl::unicode_string_view *>(DllName);
  auto Name = *FullName;

  if ( Name.istarts_with(L"aegisty") || Name.iequals(L"NCCrashReporter.dll") ) {
    *DllHandle = nullptr;
    return STATUS_DLL_NOT_FOUND;
  }
  return g_pfnLdrLoadDll(DllPath, DllCharacteristics, DllName, DllHandle);
}

decltype(&NtCreateFile) g_pfnNtCreateFile;
NTSTATUS NTAPI NtCreateFile_hook(
  PHANDLE FileHandle,
  ACCESS_MASK DesiredAccess,
  POBJECT_ATTRIBUTES ObjectAttributes,
  PIO_STATUS_BLOCK IoStatusBlock,
  PLARGE_INTEGER AllocationSize,
  ULONG FileAttributes,
  ULONG ShareAccess,
  ULONG CreateDisposition,
  ULONG CreateOptions,
  PVOID EaBuffer,
  ULONG EaLength)
{
#ifndef _WIN64
  constexpr std::array ObjectNames{
    L"\\\\.\\SICE",
    L"\\\\.\\SIWVID",
    L"\\\\.\\NTICE",
  };

  const auto ObjectName = static_cast<nt::rtl::unicode_string_view *>(ObjectAttributes->ObjectName);
  if ( std::ranges::any_of(ObjectNames, [ObjectName](const auto &Other) {
    return ObjectName->iequals(Other);
  }) ) {
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
  PHANDLE MutantHandle,
  ACCESS_MASK DesiredAccess,
  POBJECT_ATTRIBUTES ObjectAttributes,
  BOOLEAN InitialOwner)
{
  if ( ObjectAttributes ) {
    const auto ObjectName = static_cast<nt::rtl::unicode_string_view *>(ObjectAttributes->ObjectName);
    if ( ObjectName->istarts_with(L"BnSGameClient") ) {
      ObjectAttributes->ObjectName = nullptr;
      ObjectAttributes->Attributes &= ~OBJ_OPENIF;
      ObjectAttributes->RootDirectory = nullptr;
    }
  }
  return g_pfnNtCreateMutant(MutantHandle, DesiredAccess, ObjectAttributes, InitialOwner);
}

decltype(&NtOpenKeyEx) g_pfnNtOpenKeyEx;
NTSTATUS NTAPI NtOpenKeyEx_hook(
  PHANDLE KeyHandle,
  ACCESS_MASK DesiredAccess,
  POBJECT_ATTRIBUTES ObjectAttributes,
  ULONG OpenOptions)
{
  constexpr std::array ObjectNames{
    L"Software\\Wine",
    L"HARDWARE\\ACPI\\DSDT\\VBOX__"
  };

  const auto ObjectName = static_cast<nt::rtl::unicode_string_view *>(ObjectAttributes->ObjectName);
  if ( std::ranges::any_of(ObjectNames, [ObjectName](const auto &Other) {
    return ObjectName->iequals(Other);
  }) ) {
    return STATUS_OBJECT_NAME_NOT_FOUND;
  }
  return g_pfnNtOpenKeyEx(KeyHandle, DesiredAccess, ObjectAttributes, OpenOptions);
}

decltype(&NtProtectVirtualMemory) g_pfnNtProtectVirtualMemory;
NTSTATUS NTAPI NtProtectVirtualMemory_hook(
  HANDLE ProcessHandle,
  PVOID *BaseAddress,
  PSIZE_T RegionSize,
  ULONG NewProtect,
  PULONG OldProtect)
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
  HANDLE ProcessHandle,
  PROCESSINFOCLASS ProcessInformationClass,
  PVOID ProcessInformation,
  ULONG ProcessInformationLength,
  PULONG ReturnLength)
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

NTSTATUS NTAPI MyNtQuerySystemInformation(SYSTEM_INFORMATION_CLASS SystemInformationClass, PVOID *SystemInformation, PULONG ReturnLength)
{
  NTSTATUS Status;
  ULONG MyReturnLength;

  Status = g_pfnNtQuerySystemInformation(SystemInformationClass, nullptr, 0, &MyReturnLength);
  if ( Status != STATUS_INFO_LENGTH_MISMATCH )
    return Status;

  PVOID Buffer = nullptr;
  do {
    if ( Buffer )
      (VOID)RtlFreeHeap(RtlProcessHeap(), 0, Buffer);
    Buffer = RtlAllocateHeap(RtlProcessHeap(), HEAP_ZERO_MEMORY, MyReturnLength);
    if ( !Buffer )
      return STATUS_INSUFFICIENT_RESOURCES;
    Status = g_pfnNtQuerySystemInformation(SystemInformationClass, Buffer, MyReturnLength, &MyReturnLength);
  } while ( Status == STATUS_INFO_LENGTH_MISMATCH );
  if ( FAILED_NTSTATUS(Status) ) {
    (VOID)RtlFreeHeap(RtlProcessHeap(), 0, Buffer);
    *SystemInformation = nullptr;
    if ( ReturnLength )
      *ReturnLength = 0;
  } else {
    *SystemInformation = Buffer;
    if ( ReturnLength )
      *ReturnLength = MyReturnLength;
  }
  return Status;
}

NTSTATUS NTAPI MyNtQueryInformationProcess(HANDLE ProcessHandle, PROCESSINFOCLASS ProcessInformationClass, PVOID *ProcessInformation, PULONG ReturnLength)
{
  NTSTATUS Status;
  ULONG MyReturnLength;

  Status = g_pfnNtQueryInformationProcess(ProcessHandle, ProcessInformationClass, nullptr, 0, &MyReturnLength);
  if ( Status != STATUS_INFO_LENGTH_MISMATCH )
    return Status;

  PVOID Buffer = nullptr;
  do {
    if ( Buffer )
      (VOID)RtlFreeHeap(RtlProcessHeap(), 0, Buffer);
    Buffer = RtlAllocateHeap(RtlProcessHeap(), HEAP_ZERO_MEMORY, MyReturnLength);
    if ( !Buffer )
      return STATUS_INSUFFICIENT_RESOURCES;
    Status = g_pfnNtQueryInformationProcess(ProcessHandle, ProcessInformationClass, Buffer, MyReturnLength, &MyReturnLength);
  } while ( Status == STATUS_INFO_LENGTH_MISMATCH );
  if ( FAILED_NTSTATUS(Status) ) {
    (VOID)RtlFreeHeap(RtlProcessHeap(), 0, Buffer);
    *ProcessInformation = nullptr;
    if ( ReturnLength )
      *ReturnLength = 0;
  } else {
    *ProcessInformation = Buffer;
    if ( ReturnLength )
      *ReturnLength = MyReturnLength;
  }
  return Status;
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
      if (SUCCEEDED_NTSTATUS(Status) ) {
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
              PUNICODE_STRING ImageNameW32 = nullptr;
              const auto Status = MyNtQueryInformationProcess(ProcessHandle, ProcessImageFileNameWin32, (PVOID *)&ImageNameW32, nullptr);
              (VOID)NtClose(ProcessHandle);
              if ( SUCCEEDED_NTSTATUS(Status)
                && ImageNameW32->Length != 0
                && (Entry->UniqueProcessId != NtCurrentTeb()->ClientId.UniqueProcess
                  && (RtlEqualUnicodeString(&NtCurrentPeb()->ProcessParameters->ImagePathName, ImageNameW32, TRUE) || !IsVendorModule(ImageNameW32))) ) {
                RtlSecureZeroMemory(Entry, EntrySize);
                PreviousEntry->NextEntryOffset += NextEntryOffset;
                Entry = PreviousEntry;
              }
              (VOID)RtlFreeHeap(RtlProcessHeap(), 0, ImageNameW32);
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
      return MyReturnLength > SystemInformationLength ? STATUS_INFO_LENGTH_MISMATCH : Status;
    }
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
      if ( ReturnLength )
        *ReturnLength = sizeof(SYSTEM_KERNEL_DEBUGGER_INFORMATION);
      return STATUS_SUCCESS;
  }
  return g_pfnNtQuerySystemInformation(
    SystemInformationClass,
    SystemInformation,
    SystemInformationLength,
    ReturnLength);
  /*
  switch ( SystemInformationClass ) {
    case SystemSessionProcessInformation:
    case SystemProcessInformation:
    case SystemExtendedProcessInformation:
    case SystemFullProcessInformation: {
     /* ULONG MyReturnLength;
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
          do {
            PreviousEntry = Entry;
            Entry = (PSYSTEM_PROCESS_INFORMATION)((PUCHAR)PreviousEntry + PreviousEntry->NextEntryOffset);
            NextEntryOffset = Entry->NextEntryOffset;
            const auto EntrySize = NextEntryOffset ? NextEntryOffset : SizeOfBuf - (ULONG)((PUCHAR)Entry - (PUCHAR)Start);
            CLIENT_ID ClientId{.UniqueProcess = Entry->UniqueProcessId};
            OBJECT_ATTRIBUTES ObjectAttributes;
            InitializeObjectAttributes(&ObjectAttributes, nullptr, 0, nullptr, nullptr);
            HANDLE ProcessHandle;
            if ( SUCCEEDED_NTSTATUS(NtOpenProcess(&ProcessHandle, PROCESS_QUERY_LIMITED_INFORMATION, &ObjectAttributes, &ClientId)) ) {
              PUNICODE_STRING ImageNameW32 = nullptr;
              const auto Status = MyNtQueryInformationProcess(ProcessHandle, ProcessImageFileNameWin32, (PVOID *)&ImageNameW32, nullptr);
              (VOID)NtClose(ProcessHandle);
              if ( SUCCEEDED_NTSTATUS(Status)
                && ImageNameW32->Length != 0
                && (Entry->UniqueProcessId != NtCurrentTeb()->ClientId.UniqueProcess
                  && (RtlEqualUnicodeString(&NtCurrentPeb()->ProcessParameters->ImagePathName, ImageNameW32, TRUE)
                    || !IsVendorModule(ImageNameW32))) ) {
                RtlSecureZeroMemory(Entry, EntrySize);
                PreviousEntry->NextEntryOffset += NextEntryOffset;
                Entry = PreviousEntry;
              }
              (VOID)RtlFreeHeap(RtlProcessHeap(), 0, ImageNameW32);
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
      return MyReturnLength > SystemInformationLength ? STATUS_INFO_LENGTH_MISMATCH : Status;
    }
    case SystemModuleInformation:
      if ( SystemInformationLength < FIELD_OFFSET(RTL_PROCESS_MODULES, Modules) )
        return STATUS_INFO_LENGTH_MISMATCH;
      return STATUS_ACCESS_DENIED;

    case SystemKernelDebuggerInformation:
      if ( SystemInformationLength < sizeof(SYSTEM_KERNEL_DEBUGGER_INFORMATION) )
        return STATUS_INFO_LENGTH_MISMATCH;
      ((PSYSTEM_KERNEL_DEBUGGER_INFORMATION)SystemInformation)->KernelDebuggerEnabled = FALSE;
      ((PSYSTEM_KERNEL_DEBUGGER_INFORMATION)SystemInformation)->KernelDebuggerNotPresent = TRUE;
      if ( ReturnLength )
        *ReturnLength = sizeof(SYSTEM_KERNEL_DEBUGGER_INFORMATION);
      return STATUS_SUCCESS;

    case SystemModuleInformationEx:
      if ( SystemInformationLength < sizeof(RTL_PROCESS_MODULE_INFORMATION_EX) )
        return STATUS_INFO_LENGTH_MISMATCH;
      return STATUS_ACCESS_DENIED;
  }
  return g_pfnNtQuerySystemInformation(
    SystemInformationClass,
    SystemInformation,
    SystemInformationLength,
    ReturnLength);*/
}

decltype(&NtSetInformationThread) g_pfnNtSetInformationThread;
NTSTATUS NTAPI NtSetInformationThread_hook(
  HANDLE ThreadHandle,
  THREADINFOCLASS ThreadInformationClass,
  PVOID ThreadInformation,
  ULONG ThreadInformationLength)
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
  HANDLE ThreadHandle,
  PCONTEXT ThreadContext)
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
  PHANDLE ThreadHandle,
  ACCESS_MASK DesiredAccess,
  POBJECT_ATTRIBUTES ObjectAttributes,
  HANDLE ProcessHandle,
  PVOID StartRoutine, // PUSER_THREAD_START_ROUTINE
  PVOID Argument,
  ULONG CreateFlags, // THREAD_CREATE_FLAGS_*
  SIZE_T ZeroBits,
  SIZE_T StackSize,
  SIZE_T MaximumStackSize,
  PPS_ATTRIBUTE_LIST AttributeList)
{
  PROCESS_BASIC_INFORMATION ProcessInfo;

  if ( ProcessHandle == NtCurrentProcess()
    || (SUCCEEDED_NTSTATUS(g_pfnNtQueryInformationProcess(ProcessHandle, ProcessBasicInformation, &ProcessInfo, sizeof(PROCESS_BASIC_INFORMATION), nullptr))
      && ProcessInfo.UniqueProcessId == NtCurrentTeb()->ClientId.UniqueProcess) ) {

    const auto Entry = nt::rtl::pc_to_ldr_data_table_entry(StartRoutine);
    if ( Entry && Entry->DllBase == NtCurrentPeb()->ImageBaseAddress ) {
      const auto Sections = nt::rtl::image_sections(Entry->DllBase);
      const auto Section = nt::rtl::find_image_section_by_name(Sections, ".winlice");
      if ( Section != Sections.end() ) {
        const auto Start = nt::rtl::image_rva_to_va<uchar>(Entry->DllBase, Section->VirtualAddress);
        const auto End = Start + Section->Misc.VirtualSize;
        if ( StartRoutine >= Start && StartRoutine < End ) {
          const auto BaseDllName = static_cast<nt::rtl::unicode_string_view *>(&Entry->BaseDllName);
          const auto text = std::format(L"[loader3] Refusing thread creation at entry {:.{}}+{:#x}.\n",
            BaseDllName->data(),
            BaseDllName->size(),
            (ULONG_PTR)StartRoutine - (ULONG_PTR)Entry->DllBase);
          OutputDebugStringW(text.c_str());
          return STATUS_INSUFFICIENT_RESOURCES;
        }
      }
    }
  }
  return g_pfnNtCreateThreadEx(
    ThreadHandle,
    DesiredAccess,
    ObjectAttributes,
    ProcessHandle,
    StartRoutine,
    Argument,
    CreateFlags & ~THREAD_CREATE_FLAGS_HIDE_FROM_DEBUGGER,
    ZeroBits,
    StackSize,
    MaximumStackSize,
    AttributeList);
}

static inline void hide_from_peb(HMODULE hLibModule)
{
  nt::rtl::loader_lock loaderLock{};
  std::lock_guard<nt::rtl::loader_lock> guard{loaderLock};

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
  // We have to be careful inside this hook, as it could deadlock very easily.

  static std::atomic_flag flag = ATOMIC_FLAG_INIT;

  const auto status = g_pfnRtlLeaveCriticalSection(CriticalSection);
  if ( FAILED_NTSTATUS(status) )
    return status;

  if ( CriticalSection == NtCurrentPeb()->LoaderLock
    && !RtlIsCriticalSectionLocked(CriticalSection)
    && !flag.test_and_set() ) {

    std::filesystem::path path{std::move(wil::GetModuleFileNameW<std::wstring>(nullptr))};
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
        const auto plugin_info = reinterpret_cast<const plugin_info_t *>(GetProcAddress(hlib.get(), "GPluginInfo"));
        if ( plugin_info && plugin_info->sdk_version == PLUGIN_SDK_VERSION )
          GPlugins.emplace_back(std::move(hlib), plugin_info, entry.path());
      }
    }
    GPlugins.sort([](const auto &lhs, const auto &rhs) {
      return lhs.info->priority > rhs.info->priority;
    });
    std::erase_if(GPlugins, [](const auto &item) {
      // here I'm specifically not calling the init function for bnspatch
      // so that using an older build that still has anti-anti-debug hooks
      // won't break everything. xml patching is unaffected.
      const auto stem = item.path.stem();
      return _wcsicmp(stem.c_str(), L"bnspatch") != 0 && item.info->init && !item.info->init(GClientVersion);
    });
    for ( const auto &item : GPlugins ) {
      if ( item.info->hide_from_peb )
        hide_from_peb(item.hmodule.get());

      if ( item.info->erase_pe_header ) {
        const auto nt_headers = nt::rtl::image_nt_headers(item.hmodule.get());
        const nt::rtl::protect_memory protect{item.hmodule.get(), nt_headers->OptionalHeader.SizeOfHeaders, PAGE_READWRITE};
        SecureZeroMemory(item.hmodule.get(), nt_headers->OptionalHeader.SizeOfHeaders);
      }
      const auto text = std::format(L"[loader3] Loaded plugin: \"{}\" ({:#x})", item.path.c_str(), reinterpret_cast<uintptr_t>(item.hmodule.get()));
      OutputDebugStringW(text.c_str());
    }
  }
  return status;
}

HWND(NTAPI *g_pfnNtUserFindWindowEx)(HWND, HWND, PUNICODE_STRING, PUNICODE_STRING, DWORD);
HWND NTAPI NtUserFindWindowEx_hook(
  HWND hwndParent,
  HWND hwndChild,
  PUNICODE_STRING pstrClassName,
  PUNICODE_STRING pstrWindowName,
  DWORD dwType)
{
  constexpr std::array ClassNames{
#ifndef _WIN64
    L"OLLYDBG",
    L"GBDYLLO",
    L"pediy06",
#endif         
    L"FilemonClass",
    L"PROCMON_WINDOW_CLASS",
    L"RegmonClass",
    L"18467-41"
  };
  constexpr std::array WindowNames{
    L"File Monitor - Sysinternals: www.sysinternals.com",
    L"Process Monitor - Sysinternals: www.sysinternals.com",
    L"Registry Monitor - Sysinternals: www.sysinternals.com"
  };
  const auto ClassName = static_cast<nt::rtl::unicode_string_view *>(pstrClassName);
  const auto WindowName = static_cast<nt::rtl::unicode_string_view *>(pstrWindowName);
  if ( (ClassName && std::ranges::any_of(ClassNames, [ClassName](const auto &Other) { return ClassName->iequals(Other); }))
    || (WindowName && std::ranges::any_of(WindowNames, [WindowName](const auto &Other) { return WindowName->equals(Other); })) ) {
    return nullptr;
  }
  return g_pfnNtUserFindWindowEx(hwndParent, hwndChild, pstrClassName, pstrWindowName, dwType);
}

decltype(&GetSystemTimeAsFileTime) g_pfnGetSystemTimeAsFileTime;
VOID WINAPI GetSystemTimeAsFileTime_hook(LPFILETIME lpSystemTimeAsFileTime)
{
  static INIT_ONCE once;

  std::array<PVOID, 64> Buffer;
  const auto Count = RtlWalkFrameChain(Buffer.data(), SafeInt{Buffer.size()}, 0);
  const std::span<PVOID> Callers{Buffer.data(), Count};
  wil::init_once_nothrow(once, [&Callers]() {
    MEMORY_BASIC_INFORMATION mbi;
    const auto it = std::ranges::find_if(Callers, [&](PVOID Caller) {
      return VirtualQuery(Caller, &mbi, sizeof(MEMORY_BASIC_INFORMATION)) != 0
        && (mbi.State == MEM_COMMIT && (mbi.Protect & 0xff) != PAGE_NOACCESS && (mbi.Protect & PAGE_GUARD) == 0)
        && mbi.AllocationBase != wil::GetModuleInstanceHandle();
    });
    if ( it == Callers.end() || mbi.AllocationBase != NtCurrentPeb()->ImageBaseAddress )
      return E_FAIL;
    for ( const auto &item : GPlugins ) {
      if ( item.info->oep_notify )
        item.info->oep_notify(GClientVersion);
    }
    return S_OK;
  });
  return g_pfnGetSystemTimeAsFileTime(lpSystemTimeAsFileTime);
}

decltype(&K32EnumProcesses) g_pfnK32EnumProcesses;
BOOL
WINAPI
EnumProcesses(
  _Out_writes_bytes_(cb) DWORD *lpidProcess,
  _In_ DWORD cb,
  _Out_ LPDWORD lpcbNeeded
);
