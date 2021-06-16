#pragma once

#include "pch.h"
#include "pluginsdk.h"

struct plugin_item_struct
{
  wil::unique_hmodule hmodule;
  const plugin_info_t *info;
  std::filesystem::path path;
};

extern version_t GClientVersion;
extern std::list<plugin_item_struct> GPlugins;
