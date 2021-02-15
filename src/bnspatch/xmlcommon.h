#pragma once

#include <pugixml.hpp>
#include <vector>
#include <string>

#include "xmlreader.h"


struct xml_buffer_writer : pugi::xml_writer
{
  std::vector<unsigned char> result;

  virtual void write(const void *data, size_t size)
  {
    result.insert(result.end(),
      reinterpret_cast<const unsigned char *>(data),
      reinterpret_cast<const unsigned char *>(data) + size);
  }
};

template <class Char, class Traits = std::char_traits<Char>, class Alloc = std::allocator<Char>>
struct xml_basic_string_writer : pugi::xml_writer
{
  std::basic_string<Char, Traits, Alloc> result;

  virtual void write(const void *data, size_t size)
  {
    result.append(
      reinterpret_cast<const Char *>(data),
      reinterpret_cast<const Char *>(reinterpret_cast<const unsigned char *>(data) + size));
  }
};

using xml_string_writer = xml_basic_string_writer<char>;
using xml_wstring_writer = xml_basic_string_writer<wchar_t>;

pugi::xml_node convert_append_child(pugi::xml_node &parent, const XmlNode *node);

pugi::xml_parse_result convert_document(pugi::xml_document &doc, XmlDoc *xmlDoc);
