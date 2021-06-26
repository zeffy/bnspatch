#include "pch.h"
#include "pluginsdk.h"

bool  __cdecl oep_notify([[maybe_unused]] const Version version)
{
  // do stuff
  return true;
}

void __cdecl oep_notify([[maybe_unused]] const Version version)
{
  // do stuff
}

extern "C" __declspec(dllexport) PluginInfo GPluginInfo = {
#ifdef NDEBUG
  .hide_from_peb = true,
  .erase_pe_header = true,
#endif
  .oep_notify = oep_notify,
  .priority = 1,
  .target_apps = L"Client.exe;BNSR.exe"
};
