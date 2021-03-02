#pragma once

#include <cstdint>

struct version_t
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

  constexpr version_t()
    : version{0}
  {
  }

  constexpr version_t(uint64_t version)
    : version{version}
  {
  }

  constexpr version_t(uint16_t major, uint16_t minor, uint16_t build = 0, uint16_t revision = 0)
    : major{major}, minor{minor}, build{build}, revision{revision}
  {
  }

  constexpr version_t &operator=(uint64_t rhs)
  {
    version = rhs;
    return *this;
  }

  constexpr int compare(const version_t &other) const noexcept
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

  constexpr bool operator==(const version_t &other) const noexcept
  {
    return version == other.version;
  }

  constexpr bool operator!=(const version_t &other) const noexcept
  {
    return !(version == other);
  }

  constexpr auto operator<=>(const version_t &other) const noexcept
  {
    return compare(other);
  }
};

#define PLUGIN_SDK_VERSION 3

struct plugin_info_t
{
  version_t sdk_version{PLUGIN_SDK_VERSION};
  bool hide_from_peb;
  bool erase_pe_header;
  bool(__cdecl *init)(const version_t);
  void(__cdecl *oep_notify)(const version_t);
  int priority;
};
