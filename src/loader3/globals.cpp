#include "pch.h"
#include "globals.h"

version_t GClientVersion;
std::list<std::pair<wil::unique_hmodule, const plugin_info_t *>> GPlugins;
