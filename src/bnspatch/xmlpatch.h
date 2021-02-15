#pragma once

#include <filesystem>
#include <unordered_map>
#include <unordered_set>
#include <map>
#include <functional>
#include <string>
#include <string_view>

#include <fnv1a.h>
#include <pugixml.hpp>

std::wstring &ReplaceStringInPlace(std::wstring &haystack,
  const std::wstring_view &search,
  const std::wstring_view &replace);

const std::multimap<std::filesystem::path, std::vector<std::pair<std::wstring, std::wstring>>> get_or_load_addons();
std::filesystem::path documents_path();
std::vector<std::pair<std::wstring, std::wstring>> get_relevant_addons(const wchar_t *xml);
std::vector<pugi::xml_node> get_relevant_patches(const wchar_t *xml);
void apply_patches(pugi::xml_document &src, pugi::xml_encoding, const std::vector<pugi::xml_node> &patches);
const pugi::xml_document &get_or_load_patches();
void preprocess(pugi::xml_document &patches_doc, const std::filesystem::path &path, std::unordered_set<fnv1a::type> &include_guard);
std::filesystem::path patches_path();
void patch_node(
  pugi::xml_document &doc,
  const pugi::xml_encoding encoding,
  const pugi::xpath_node &ctx,
  const pugi::xml_object_range<pugi::xml_node_iterator> &children,
  std::unordered_map<fnv1a::type, pugi::xml_node> &saved_nodes);
pugi::xml_parse_result try_load_file(
  pugi::xml_document &document,
  const std::filesystem::path &path,
  unsigned int options = pugi::parse_default,
  pugi::xml_encoding encoding = pugi::encoding_auto);
