#pragma once
#include <phnt_windows.h>
#include <phnt.h>
#include "pluginsdk.h"

extern decltype(&GetPrivateProfileStringW) g_pfnGetPrivateProfileStringW;
DWORD WINAPI GetPrivateProfileStringW_hook(
  LPCWSTR lpAppName,
  LPCWSTR lpKeyName,
  LPCWSTR lpDefault,
  LPWSTR lpReturnedString,
  DWORD nSize,
  LPCWSTR lpFileName);
