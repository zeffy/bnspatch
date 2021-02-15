#pragma once
#include <list>
#include <optional>
#include <utility>
#include <wil/resource.h>
#include <pluginsdk.h>

extern std::optional<version_t> GClientVersion;
extern std::list<std::pair<wil::unique_hmodule, const plugin_info_t *>> GPlugins;
