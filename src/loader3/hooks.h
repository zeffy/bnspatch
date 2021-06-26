#pragma once

#include <phnt_windows.h>
#include <phnt.h>

extern decltype(&LdrGetDllHandle) g_pfnLdrGetDllHandle;
NTSTATUS NTAPI LdrGetDllHandle_hook(
  _In_opt_ PWSTR DllPath,
  _In_opt_ PULONG DllCharacteristics,
  _In_ PUNICODE_STRING DllName,
  _Out_ PVOID *DllHandle);

extern decltype(&LdrLoadDll) g_pfnLdrLoadDll;
NTSTATUS NTAPI LdrLoadDll_hook(
  _In_opt_ PWSTR DllPath,
  _In_opt_ PULONG DllCharacteristics,
  _In_ PUNICODE_STRING DllName,
  _Out_ PVOID *DllHandle);

extern decltype(&NtCreateFile) g_pfnNtCreateFile;
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
  _In_ ULONG EaLength);

extern decltype(&NtCreateMutant) g_pfnNtCreateMutant;
NTSTATUS NTAPI NtCreateMutant_hook(
  _Out_ PHANDLE MutantHandle,
  _In_ ACCESS_MASK DesiredAccess,
  _In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
  _In_ BOOLEAN InitialOwner);

extern decltype(&NtOpenKeyEx) g_pfnNtOpenKeyEx;
NTSTATUS NTAPI NtOpenKeyEx_hook(
  _Out_ PHANDLE KeyHandle,
  _In_ ACCESS_MASK DesiredAccess,
  _In_ POBJECT_ATTRIBUTES ObjectAttributes,
  _In_ ULONG OpenOptions);

extern decltype(&NtProtectVirtualMemory) g_pfnNtProtectVirtualMemory;
NTSTATUS NTAPI NtProtectVirtualMemory_hook(
  _In_ HANDLE ProcessHandle,
  _Inout_ PVOID *BaseAddress,
  _Inout_ PSIZE_T RegionSize,
  _In_ ULONG NewProtect,
  _Out_ PULONG OldProtect);

extern decltype(&NtQueryInformationProcess) g_pfnNtQueryInformationProcess;
NTSTATUS NTAPI NtQueryInformationProcess_hook(
  _In_ HANDLE ProcessHandle,
  _In_ PROCESSINFOCLASS ProcessInformationClass,
  _Out_writes_bytes_(ProcessInformationLength) PVOID ProcessInformation,
  _In_ ULONG ProcessInformationLength,
  _Out_opt_ PULONG ReturnLength);

extern decltype(&NtQuerySystemInformation) g_pfnNtQuerySystemInformation;
NTSTATUS NTAPI NtQuerySystemInformation_hook(
  _In_ SYSTEM_INFORMATION_CLASS SystemInformationClass,
  _Out_writes_bytes_opt_(SystemInformationLength) PVOID SystemInformation,
  _In_ ULONG SystemInformationLength,
  _Out_opt_ PULONG ReturnLength);

extern decltype(&NtSetInformationThread) g_pfnNtSetInformationThread;
NTSTATUS NTAPI NtSetInformationThread_hook(
  _In_ HANDLE ThreadHandle,
  _In_ THREADINFOCLASS ThreadInformationClass,
  _In_reads_bytes_(ThreadInformationLength) PVOID ThreadInformation,
  _In_ ULONG ThreadInformationLength);

extern decltype(&NtGetContextThread) g_pfnNtGetContextThread;
NTSTATUS NTAPI NtGetContextThread_hook(
  _In_ HANDLE ThreadHandle,
  _Inout_ PCONTEXT ThreadContext);

extern decltype(&NtCreateThreadEx) g_pfnNtCreateThreadEx;
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
  _In_opt_ PPS_ATTRIBUTE_LIST AttributeList);

extern decltype(&FindWindowA) g_pfnFindWindowA;
HWND WINAPI FindWindowA_hook(
  _In_opt_ LPCSTR lpClassName,
  _In_opt_ LPCSTR lpWindowName);

extern decltype(&GetSystemTimeAsFileTime) g_pfnGetSystemTimeAsFileTime;
VOID WINAPI GetSystemTimeAsFileTime_hook(
  _Out_ LPFILETIME lpSystemTimeAsFileTime);
