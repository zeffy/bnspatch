#pragma once

#include <phnt_windows.h>
#include <phnt.h>

extern decltype(&LdrGetDllHandle) g_pfnLdrGetDllHandle;
NTSTATUS NTAPI LdrGetDllHandle_hook(
  PWSTR DllPath,
  PULONG DllCharacteristics,
  PUNICODE_STRING DllName,
  PVOID *DllHandle);

extern decltype(&LdrLoadDll) g_pfnLdrLoadDll;
NTSTATUS NTAPI LdrLoadDll_hook(
  PWSTR DllPath,
  PULONG DllCharacteristics,
  PUNICODE_STRING DllName,
  PVOID *DllHandle);

extern decltype(&NtCreateFile) g_pfnNtCreateFile;
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
  ULONG EaLength);

extern decltype(&NtCreateMutant) g_pfnNtCreateMutant;
NTSTATUS NTAPI NtCreateMutant_hook(
  PHANDLE MutantHandle,
  ACCESS_MASK DesiredAccess,
  POBJECT_ATTRIBUTES ObjectAttributes,
  BOOLEAN InitialOwner);

extern decltype(&NtOpenKeyEx) g_pfnNtOpenKeyEx;
NTSTATUS NTAPI NtOpenKeyEx_hook(
  PHANDLE KeyHandle,
  ACCESS_MASK DesiredAccess,
  POBJECT_ATTRIBUTES ObjectAttributes,
  ULONG OpenOptions);

extern decltype(&NtProtectVirtualMemory) g_pfnNtProtectVirtualMemory;
NTSTATUS NTAPI NtProtectVirtualMemory_hook(
  HANDLE ProcessHandle,
  PVOID *BaseAddress,
  PSIZE_T RegionSize,
  ULONG NewProtect,
  PULONG OldProtect);

extern decltype(&NtQueryInformationProcess) g_pfnNtQueryInformationProcess;
NTSTATUS NTAPI NtQueryInformationProcess_hook(
  HANDLE ProcessHandle,
  PROCESSINFOCLASS ProcessInformationClass,
  PVOID ProcessInformation,
  ULONG ProcessInformationLength,
  PULONG ReturnLength);

extern decltype(&NtQuerySystemInformation) g_pfnNtQuerySystemInformation;
NTSTATUS NTAPI NtQuerySystemInformation_hook(
  SYSTEM_INFORMATION_CLASS SystemInformationClass,
  PVOID SystemInformation,
  ULONG SystemInformationLength,
  PULONG ReturnLength);

extern decltype(&NtSetInformationThread) g_pfnNtSetInformationThread;
NTSTATUS NTAPI NtSetInformationThread_hook(
  HANDLE ThreadHandle,
  THREADINFOCLASS ThreadInformationClass,
  PVOID ThreadInformation,
  ULONG ThreadInformationLength);

extern decltype(&NtGetContextThread) g_pfnNtGetContextThread;
NTSTATUS NTAPI NtGetContextThread_hook(
  HANDLE ThreadHandle,
  PCONTEXT ThreadContext);

extern decltype(&NtCreateThreadEx) g_pfnNtCreateThreadEx;
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
  PPS_ATTRIBUTE_LIST AttributeList);

extern decltype(&FindWindowA) g_pfnFindWindowA;
HWND WINAPI FindWindowA_hook(
  _In_opt_ LPCSTR lpClassName,
  _In_opt_ LPCSTR lpWindowName);

extern decltype(&SHTestTokenMembership) g_pfnSHTestTokenMembership;
BOOL STDAPICALLTYPE SHTestTokenMembership_hook(_In_opt_ HANDLE hToken, ULONG ulRID);

extern decltype(&GetSystemTimeAsFileTime) g_pfnGetSystemTimeAsFileTime;
VOID WINAPI GetSystemTimeAsFileTime_hook(LPFILETIME lpSystemTimeAsFileTime);
