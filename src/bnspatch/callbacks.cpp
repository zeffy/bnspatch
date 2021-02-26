#include "pch.h"
#include <ehdata.h>
#include <rttidata.h>
#include "hooks.h"
#include "pluginsdk.h"
#include "xmlhooks.h"

bool __cdecl init([[maybe_unused]] const version_t client_version)
{
  NtCurrentPeb()->BeingDebugged = FALSE;

  THROW_IF_WIN32_ERROR(DetourTransactionBegin());
  THROW_IF_WIN32_ERROR(DetourUpdateThread(NtCurrentThread()));

  const auto hNtDll = GetModuleHandleW(RtlNtdllName);
  THROW_LAST_ERROR_IF_NULL(hNtDll);
#ifdef _X86_
  THROW_IF_WIN32_ERROR(DetourAttach(hNtDll, "LdrGetDllHandle", &g_pfnLdrGetDllHandle, &LdrGetDllHandle_hook));
#endif
  THROW_IF_WIN32_ERROR(DetourAttach(hNtDll, "LdrLoadDll", &g_pfnLdrLoadDll, LdrLoadDll_hook));
  THROW_IF_WIN32_ERROR(DetourAttach(hNtDll, "NtCreateFile", &g_pfnNtCreateFile, NtCreateFile_hook));
  THROW_IF_WIN32_ERROR(DetourAttach(hNtDll, "NtCreateMutant", &g_pfnNtCreateMutant, NtCreateMutant_hook));
  THROW_IF_WIN32_ERROR(DetourAttach(hNtDll, "NtOpenKeyEx", &g_pfnNtOpenKeyEx, NtOpenKeyEx_hook));
  THROW_IF_WIN32_ERROR(DetourAttach(hNtDll, "NtProtectVirtualMemory", &g_pfnNtProtectVirtualMemory, NtProtectVirtualMemory_hook));
  THROW_IF_WIN32_ERROR(DetourAttach(hNtDll, "NtQuerySystemInformation", &g_pfnNtQuerySystemInformation, NtQuerySystemInformation_hook));
#ifdef _AMD64_
  THROW_IF_WIN32_ERROR(DetourAttach(hNtDll, "NtQueryInformationProcess", &g_pfnNtQueryInformationProcess, NtQueryInformationProcess_hook));
  THROW_IF_WIN32_ERROR(DetourAttach(hNtDll, "NtSetInformationThread", &g_pfnNtSetInformationThread, NtSetInformationThread_hook));
  THROW_IF_WIN32_ERROR(DetourAttach(hNtDll, "NtGetContextThread", &g_pfnNtGetContextThread, NtGetContextThread_hook));
#endif

  THROW_IF_WIN32_ERROR(DetourAttach(L"user32.dll", "FindWindowA", &g_pfnFindWindowA, FindWindowA_hook));

  THROW_IF_WIN32_ERROR(DetourTransactionCommit());
  return true;
}

void __cdecl oep_notify([[maybe_unused]] const version_t client_version)
{
  const auto nt_headers = nt::rtl::image_nt_headers(nullptr);
  const auto sections = nt::rtl::image_sections(nullptr);
  for ( const auto &section_header : sections ) {
    if ( (section_header.Characteristics & IMAGE_SCN_MEM_READ) != IMAGE_SCN_MEM_READ
      || section_header.VirtualAddress + section_header.Misc.VirtualSize > nt_headers->OptionalHeader.SizeOfImage )
      continue;

    const auto section = nt::rtl::image_rva_to_va<UCHAR>(nullptr, section_header.VirtualAddress);
    const char name[] = ".?AVXmlReaderImpl@@";
    for ( auto ptr = section;
      ptr + sizeof(TypeDescriptor) <= section + section_header.Misc.VirtualSize;
      ptr = (PUCHAR)(((ULONG_PTR)ptr + (alignof(TypeDescriptor) + 1)) & ~(alignof(TypeDescriptor) - 1)) ) {
      if ( !std::equal(std::begin(name), std::end(name), ptr + offsetof(TypeDescriptor, name)) )
        continue;

      const auto tmp = (TypeDescriptor *)ptr;
#if _RTTI_RELATIVE_TYPEINFO
      const auto ptd = (int)((ULONG_PTR)tmp - (ULONG_PTR)NtCurrentPeb()->ImageBaseAddress);
#else
      const auto ptd = tmp;
#endif
      for ( const auto &section_header2 : sections ) {
        if ( (section_header2.Characteristics & IMAGE_SCN_MEM_READ) != IMAGE_SCN_MEM_READ
          || section_header2.VirtualAddress + section_header2.Misc.VirtualSize > nt_headers->OptionalHeader.SizeOfImage )
          continue;

        const auto section2 = nt::rtl::image_rva_to_va<UCHAR>(nullptr, section_header2.VirtualAddress);
        for ( auto ptr2 = section2;
          ptr2 + sizeof(_RTTICompleteObjectLocator) <= section2 + section_header2.Misc.VirtualSize;
          ptr2 = (PUCHAR)(((ULONG_PTR)ptr2 + (alignof(_RTTICompleteObjectLocator) + 1)) & ~(alignof(_RTTICompleteObjectLocator) - 1)) ) {
          if ( *(decltype(_RTTICompleteObjectLocator::pTypeDescriptor) *)(ptr2 + offsetof(_RTTICompleteObjectLocator, pTypeDescriptor)) != ptd )
            continue;

          const auto col = (_RTTICompleteObjectLocator *)ptr2;
          for ( auto ptr3 = section2;
            ptr3 + sizeof(_RTTICompleteObjectLocator *) <= section2 + section_header2.Misc.VirtualSize;
            ptr3 = (PUCHAR)(((ULONG_PTR)ptr3 + (alignof(_RTTICompleteObjectLocator *) + 1)) & ~(alignof(_RTTICompleteObjectLocator *) - 1)) ) {
            if ( *(_RTTICompleteObjectLocator **)ptr3 != col )
              continue;

            const auto vfptr = (void **)(ptr3 + sizeof(_RTTICompleteObjectLocator *));
            THROW_IF_WIN32_ERROR(DetourTransactionBegin());
            THROW_IF_WIN32_ERROR(DetourUpdateThread(NtCurrentThread()));
            g_pfnReadFile = reinterpret_cast<decltype(g_pfnReadFile)>(vfptr[6]);
            THROW_IF_WIN32_ERROR(DetourAttach(reinterpret_cast<PVOID *>(&g_pfnReadFile), ReadFile_hook));
            g_pfnReadMem = reinterpret_cast<decltype(g_pfnReadMem)>(vfptr[7]);
            THROW_IF_WIN32_ERROR(DetourAttach(reinterpret_cast<PVOID *>(&g_pfnReadMem), ReadMem_hook));
            THROW_IF_WIN32_ERROR(DetourTransactionCommit());
            return;
          }
        }
      }
    }
  }
}

extern "C" __declspec(dllexport) plugin_info_t GPluginInfo = {
#ifdef NDEBUG
  .hide_from_peb = true,
  .erase_pe_header = true,
#endif
  .init = init,
  .oep_notify = oep_notify,
  .priority = 1
};
