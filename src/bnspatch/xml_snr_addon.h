#pragma once
#include "pch.h"

class xml_snr_addon_base
{
public:
  struct xml_snr_addon_data
  {
    std::vector<std::pair<std::wstring, std::wstring>> snr;
    std::optional<std::wstring> description;
  };

protected:
  std::wstring _name;
  std::multimap<std::wstring, xml_snr_addon_data> _map;

  static void clean_file_str(std::wstring &str);

public:
  bool is_valid() const;
  const std::wstring &name() const;
  bool save(const std::filesystem::path &path) const;
  void get(const wchar_t *xml, std::vector<std::reference_wrapper<const std::pair<std::wstring, std::wstring>>> &v) const;

  static void replace_all(std::wstring &str, const std::wstring_view &s, const std::wstring_view &r);
};

class xml_snr_legacy_addon : public xml_snr_addon_base
{
  static void clean_snr_str(std::wstring &str);

public:
  xml_snr_legacy_addon(const std::filesystem::path &path);
};

class xml_snr_addon : public xml_snr_addon_base
{
public:
  xml_snr_addon(const std::filesystem::path &path);
};
