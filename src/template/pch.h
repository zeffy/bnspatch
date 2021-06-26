// pch.h: This is a precompiled header file.
// Files listed below are compiled only once, improving build performance for future builds.
// This also affects IntelliSense performance, including code completion and many code browsing features.
// However, files listed here are ALL re-compiled if any one of them is updated between builds.
// Do not add files here that you will be updating frequently as this negates the performance advantage.

#ifndef PCH_H
#define PCH_H

// add headers that you want to pre-compile here
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#define RPC_USE_NATIVE_WCHAR
#include <phnt_windows.h>
#include <phnt.h>
#pragma comment( lib, "ntdll.lib" )

#ifndef RESULT_DIAGNOSTICS_LEVEL
#define RESULT_DIAGNOSTICS_LEVEL 0
#endif

#include <wil/stl.h>
#include <wil/win32_helpers.h>
#include <wil/resource.h>
#include <wil/result.h>

#endif //PCH_H
