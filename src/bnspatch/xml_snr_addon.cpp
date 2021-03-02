#include "pch.h"
#include "xml_snr_addon.h"
#include "FastWildCompare.hpp"

void xml_snr_addon_base::clean_file_str(std::wstring &str)
{
  replace_all(str, L"\\\\", L"\\");
  replace_all(str, L"/", L"\\");
}

void xml_snr_addon_base::replace_all(std::wstring &str, const std::wstring_view &s, const std::wstring_view &r)
{
  size_t pos = 0;
  while ( (pos = str.find(s, pos)) != std::wstring::npos ) {
    str.replace(pos, s.size(), r);
    pos += r.size();
  }
}

bool xml_snr_addon_base::is_valid() const
{
  return !_map.empty();
}

const std::wstring &xml_snr_addon_base::name() const
{
  return _name;
}

bool xml_snr_addon_base::save(const std::filesystem::path &path) const
{
  pugi::xml_document document;
  auto decl = document.append_child(pugi::node_declaration);
  decl.append_attribute(L"version") = L"1.0";
  decl.append_attribute(L"encoding") = L"utf-8";

  auto files_node = document.append_child(L"files");
  for ( const auto &[file, data] : _map ) {
    auto file_node = files_node.append_child(L"file");
    file_node.append_attribute(L"path") = file.c_str();
    for ( const auto &[search, replace] : data.snr ) {
      file_node.append_child(L"search").append_child(pugi::node_cdata).set_value(search.c_str());
      file_node.append_child(L"replace").append_child(pugi::node_cdata).set_value(replace.c_str());
    }

    auto description_node = file_node.append_child(L"description");
    if ( data.description )
      description_node.append_child(pugi::node_pcdata).set_value(data.description->c_str());
  }

  return document.save_file(path.c_str(), L"  ");
}

void xml_snr_addon_base::get(const wchar_t *xml, std::vector<std::reference_wrapper<const std::pair<std::wstring, std::wstring>>> &v) const
{
  for ( const auto &[pattern, data] : _map ) {
    // remove first path node (which is typically like "xml[bit].dat.files\\")
    std::wstring_view view{pattern};
    const auto off = view.find_first_not_of(L'\\', view.find_first_of(L'\\'));
    view.remove_prefix(off);

    if ( FastWildCompareW(xml, view.data()) ) {
      for ( const auto &item : data.snr )
        v.emplace_back(std::cref(item));
    }
  }
}

void xml_snr_legacy_addon::clean_snr_str(std::wstring &str)
{
  replace_all(str, L"[NewLine]", L"\n");
  replace_all(str, L"NewLine", L"\n");
}

xml_snr_legacy_addon::xml_snr_legacy_addon(const std::filesystem::path &path)
{
  std::wstring line;
  std::optional<std::wstring> fname;
  std::vector<std::wstring> search_vec;
  std::vector<std::wstring> replace_vec;
  std::optional<std::wstring> description;

  _name = std::move(path.stem());

  std::wifstream stream{path};
  stream.imbue(std::locale{stream.getloc(), new std::codecvt_utf8<wchar_t, 0x10ffff, std::consume_header>});

  while ( std::getline(stream, line) ) {
    const auto ofs = line.find(L'=');
    if ( ofs == std::wstring::npos )
      continue;

    const auto key = boost::trim_copy(std::wstring_view{line.c_str(), ofs});
    const auto value = boost::trim_copy(std::wstring_view{&line[ofs + 1]});

    if ( key == L"FileName" ) {
      if ( fname ) {
        // New addon in same file, at this point Searches should match Replacements,
        // and there should be a description.
        if ( search_vec.size() != replace_vec.size() ) {
          _map.clear();
          return;
        }

        xml_snr_addon_data data;
        for ( const auto &[s, r] : boost::combine(search_vec, replace_vec) )
          data.snr.emplace_back(std::move(s), std::move(r));

        search_vec.clear();
        replace_vec.clear();

        data.description.swap(description);
        _map.emplace(std::move(*fname), std::move(data));
      }
      fname.emplace(value);
      clean_file_str(*fname);
    } else if ( key == L"Search" ) {
      std::wstring str{value};
      clean_snr_str(str);
      search_vec.emplace_back(std::move(str));
    } else if ( key == L"Replace" ) {
      std::wstring str{value};
      clean_snr_str(str);
      replace_vec.emplace_back(std::move(str));
    } else if ( key == L"Description" ) {
      description.emplace(value);
    }
  }

  if ( fname && description && search_vec.size() == replace_vec.size() ) {
    xml_snr_addon_data data;
    for ( const auto &[s, r] : boost::combine(search_vec, replace_vec) )
      data.snr.emplace_back(std::move(s), std::move(r));
    data.description.swap(description);
    _map.emplace(std::move(*fname), std::move(data));
  } else {
    _map.clear();
  }
}

xml_snr_addon::xml_snr_addon(const std::filesystem::path &path)
{
  pugi::xml_document document;
  document.load_file(path.c_str());

  const auto document_element = document.document_element();
  if ( std::wcscmp(document_element.name(), L"files") != 0 )
    return;

  for ( const auto file_node : document_element.children(L"file") ) {
    const auto path_attribute = file_node.attribute(L"path");
    if ( !path_attribute )
      continue;

    std::wstring fname{path_attribute.value()};
    clean_file_str(fname);

    if ( fname.empty() )
      continue;

    const auto search_rng = file_node.children(L"search");
    const auto replace_rng = file_node.children(L"replace");

    if ( std::distance(search_rng.begin(), search_rng.end()) != std::distance(replace_rng.begin(), replace_rng.end()) )
      continue;

    xml_snr_addon_data data;
    for ( const auto &[s, r] : boost::combine(search_rng, replace_rng) )
      data.snr.emplace_back(s.text().get(), r.text().get());

    const auto description_node = file_node.child(L"description");
    if ( description_node )
      data.description.emplace(description_node.text().get());
    _map.emplace(std::move(fname), std::move(data));
  }
}
