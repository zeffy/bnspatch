#pragma once

#include <cstdint>

struct Version
{
  union
  {
    struct
    {
      uint16_t major;
      uint16_t minor;
      uint16_t build;
      uint16_t revision;
    };
    uint64_t version;
  };

  constexpr Version()
    : version{0}
  {
  }

  constexpr Version(uint64_t version)
    : version{version}
  {
  }

  constexpr Version(uint16_t major, uint16_t minor, uint16_t build = 0, uint16_t revision = 0)
    : major{major}, minor{minor}, build{build}, revision{revision}
  {
  }

  constexpr Version &operator=(uint64_t rhs)
  {
    version = rhs;
    return *this;
  }

  constexpr int compare(const Version &other) const noexcept
  {
    if ( major != other.major )
      return major > other.major ? 1 : -1;

    if ( minor != other.minor )
      return minor > other.minor ? 1 : -1;

    if ( build != other.build )
      return build > other.build ? 1 : -1;

    if ( revision != other.revision )
      return revision > other.revision ? 1 : -1;

    return 0;
  }

  constexpr bool operator==(const Version &other) const noexcept
  {
    return version == other.version;
  }

  constexpr bool operator!=(const Version &other) const noexcept
  {
    return !(version == other);
  }

  constexpr auto operator<=>(const Version &other) const noexcept
  {
    return compare(other);
  }
};

constexpr Version PLUGIN_SDK_VERSION{3,1,0,0};

struct PluginInfo
{
  Version sdk_version{PLUGIN_SDK_VERSION};
  bool hide_from_peb;
  bool erase_pe_header;
  bool(__cdecl *init)(const Version version);
  void(__cdecl *oep_notify)(const Version version);
  int priority;
  const wchar_t *target_apps; // prior to 3.1 this is assumed to be L"Client.exe\0BNSR.exe\0"
};
