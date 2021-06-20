#pragma once

#include "pch.h"

template<SIZE_T Depth = 1>
class tls_recursion_guard
{
public:
  tls_recursion_guard() : TlsIndex{TlsAlloc()} {
    THROW_IF_WIN32_BOOL_FALSE(TlsSetValue(TlsIndex, nullptr));
  }

  ~tls_recursion_guard()
  {
    THROW_IF_WIN32_BOOL_FALSE(TlsFree(TlsIndex));
  }

  bool try_lock()
  {
    const auto TlsValue = (SIZE_T)TlsGetValue(TlsIndex);
    if ( !TlsValue )
      THROW_IF_WIN32_ERROR(GetLastError());
    if ( TlsValue < Depth ) {
      THROW_IF_WIN32_BOOL_FALSE(TlsSetValue(TlsIndex, (LPVOID)(TlsValue + 1)));
      return true;
    }
    return false;
  }

  void unlock()
  {
    const auto TlsValue = (SIZE_T)TlsGetValue(TlsIndex);
    if ( !TlsValue )
      THROW_IF_WIN32_ERROR(GetLastError());
    THROW_IF_WIN32_BOOL_FALSE(TlsSetValue(TlsIndex, (LPVOID)(TlsValue - 1)));
  }

private:
  DWORD TlsIndex;
};
