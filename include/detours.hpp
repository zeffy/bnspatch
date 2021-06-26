#pragma once

#include <type_traits>
#include <detours/detours.h>
#include <wil/resource.h>
#include <wil/result.h>

template <typename Ty, typename = std::enable_if_t<std::is_function_v<Ty>>>
inline LONG WINAPI DetourAttach(Ty *&pPointer, Ty *pDetour)
{
  return DetourAttachEx(&(PVOID &)pPointer, pDetour, nullptr, nullptr, nullptr);
}

template <typename Ty, typename = std::enable_if_t<std::is_function_v<Ty>>>
inline LONG WINAPI DetourAttach(HMODULE hModule, PCSTR pProcName, Ty *&pPointer, Ty *pDetour)
{
  if ( !hModule ) return ERROR_INVALID_PARAMETER;

  pPointer = reinterpret_cast<Ty *>(GetProcAddress(hModule, pProcName));
  RETURN_LAST_ERROR_IF_NULL(pPointer);

  return DetourAttach(pPointer, pDetour);
}

template <typename Ty, typename = std::enable_if_t<std::is_function_v<Ty>>>
inline LONG WINAPI DetourAttach(PCWSTR pModuleName, PCSTR pProcName, Ty *&pPointer, Ty *pDetour)
{
  if ( !pModuleName ) return ERROR_INVALID_PARAMETER;

  wil::unique_hmodule hModule;
  RETURN_LAST_ERROR_IF(!GetModuleHandleExW(0, pModuleName, &hModule));

  return DetourAttach(hModule.get(), pProcName, pPointer, pDetour);
}

template <typename Ty, typename = std::enable_if_t<std::is_function_v<Ty>>>
inline LONG WINAPI DetourAttach(PCSTR pModuleName, PCSTR pProcName, Ty *&pPointer, Ty *pDetour)
{
  if ( !pModuleName ) return ERROR_INVALID_PARAMETER;

  wil::unique_hmodule hModule;
  RETURN_LAST_ERROR_IF(!GetModuleHandleExA(0, pModuleName, &hModule));

  return DetourAttach(hModule.get(), pProcName, pPointer, pDetour);
}
