#include "pch.h"

bool WLIsProtected()
{
  static INIT_ONCE InitOnce = INIT_ONCE_STATIC_INIT;
  static bool IsProtected;

  wil::init_once_nothrow(InitOnce, []() {
    if ( GetEnvironmentVariableW(L"WLProjectName", nullptr, 0) != ERROR_ENVVAR_NOT_FOUND ) {
      IsProtected = true;
      return S_OK;
    }

    const wil::unique_environstrings_ptr penv{GetEnvironmentStringsW()};
    if ( penv ) {
      for ( auto pwstr = penv.get(); *pwstr; pwstr = wcschr(pwstr, 0) + 1 ) {
        const auto token = wcschr(pwstr, L'=');
        if ( token ) {
          *token = 0;
          if ( _stricmp((PCSTR)pwstr, "WLProjectName") == 0 ) {
            IsProtected = true;
            return S_OK;
          }
          pwstr = token + 1;
        }
      }
    }
    return S_OK;
  });
  return IsProtected;
}
