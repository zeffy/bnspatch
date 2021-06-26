#pragma once

#include "pch.h"
#include "pluginsdk.h"

struct Plugin
{
  wil::unique_hmodule hmodule;
  const PluginInfo *info;
  std::filesystem::path path;
};

extern Version GVersion;
extern std::list<Plugin> GPlugins;

