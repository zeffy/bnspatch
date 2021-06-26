#pragma once

#include "pch.h"

template<SIZE_T Depth = 1>
class thread_local_mutex
{
public:
  thread_local_mutex()
  {
    TlsIndex = TlsAlloc();
    THROW_LAST_ERROR_IF(TlsIndex == TLS_OUT_OF_INDEXES);
    THROW_IF_WIN32_BOOL_FALSE(TlsSetValue(TlsIndex, nullptr));
  }

  ~thread_local_mutex()
  {
    THROW_IF_WIN32_BOOL_FALSE(TlsFree(TlsIndex));
  }

  bool try_lock()
  {
    const auto TlsValue = (ULONG_PTR)TlsGetValue(TlsIndex);
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
    const auto TlsValue = (ULONG_PTR)TlsGetValue(TlsIndex);
    if ( !TlsValue )
      THROW_IF_WIN32_ERROR(GetLastError());
    THROW_IF_WIN32_BOOL_FALSE(TlsSetValue(TlsIndex, (LPVOID)(TlsValue - 1)));
  }

private:
  DWORD TlsIndex;
};
