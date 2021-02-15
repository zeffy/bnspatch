#include "pch.h"
#include "globals.h"

std::optional<version_t> GClientVersion;
std::list<std::pair<wil::unique_hmodule, const plugin_info_t *>> GPlugins;
