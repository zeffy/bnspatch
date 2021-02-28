#include "pch.h"
#include "globals.h"
#include "hooks.h"
#include "pluginsdk.h"

decltype(&GetPrivateProfileStringW) g_pfnGetPrivateProfileStringW;
DWORD WINAPI GetPrivateProfileStringW_hook(
  LPCWSTR lpAppName,
  LPCWSTR lpKeyName,
  LPCWSTR lpDefault,
  LPWSTR lpReturnedString,
  DWORD nSize,
  LPCWSTR lpFileName)
{
  static std::once_flag once;

  try {
    std::call_once(once, [&]() {
      if ( !GClientVersion )
        return;

      if ( !lpFileName || _wcsicmp(PathFindFileNameW(lpFileName), L"SystemText.ini") != 0 )
        throw std::exception{};

      for ( const auto &[hlib, plugin_info] : GPlugins ) {
        if ( plugin_info->oep_notify )
          plugin_info->oep_notify(*GClientVersion);
      }
    });
  } catch ( ... ) {
  }
  return g_pfnGetPrivateProfileStringW(lpAppName, lpKeyName, lpDefault, lpReturnedString, nSize, lpFileName);
}
