#pragma once

#include "pluginsdk.h"

bool __cdecl init([[maybe_unused]] const version_t client_version);
void __cdecl oep_notify([[maybe_unused]] const version_t client_version);
