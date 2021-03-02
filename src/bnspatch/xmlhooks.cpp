#include "pch.h"
#include "FastWildCompare.hpp"
#include "xmlcommon.h"
#include "xmlhooks.h"
#include "xmlpatch.h"
#include "xmlreader.h"

XmlDoc *(__thiscall *g_pfnReadMem)(const XmlReader *, const unsigned char *, unsigned int, const wchar_t *, XmlPieceReader *);
XmlDoc *thiscall_(ReadMem_hook, const XmlReader *thisptr, const unsigned char *mem, unsigned int size, const wchar_t *xmlFileNameForLogging, XmlPieceReader *xmlPieceReader)
{
  if ( !mem || !size )
    return nullptr;

  if ( xmlFileNameForLogging && *xmlFileNameForLogging ) {
#ifdef _DEBUG
    OutputDebugStringW(xmlFileNameForLogging);
#endif

    const auto patches = get_relevant_patches(xmlFileNameForLogging);
    const auto addons = get_relevant_addons(xmlFileNameForLogging);
    if ( !patches.empty() || !addons.empty() ) {
      pugi::xml_document doc;
      pugi::xml_parse_result res;

      if ( thisptr->IsBinary(mem, size) ) {
        auto xmlDoc = g_pfnReadMem(thisptr, mem, size, xmlFileNameForLogging, xmlPieceReader);
        if ( !xmlDoc )
          return nullptr;

        res = convert_document(doc, xmlDoc);
        thisptr->Close(xmlDoc);

        if ( !addons.empty() && res.encoding == pugi::encoding_utf16_le ) {
          xml_wstring_writer writer;
          doc.save(writer, L"", pugi::format_default | pugi::format_no_declaration, res.encoding);
          
          // apply addons
          for ( const auto &addon : addons ) {
            const auto &ref = addon.get();
            boost::replace_all(writer.result, ref.first, ref.second);
          }
          // reload document
          res = doc.load_string(writer.result.c_str());
        }
      } else {
        res = doc.load_buffer(mem, size);
      }

      if ( res ) {
        //apply patches
        apply_patches(doc, res.encoding, patches);

        xml_buffer_writer writer;
        doc.save(writer, nullptr, pugi::format_raw | pugi::format_no_declaration, res.encoding);
        return g_pfnReadMem(
          thisptr,
          writer.result.data(),
          SafeInt(writer.result.size()),
          xmlFileNameForLogging,
          xmlPieceReader);
      }
    }
  }
  return g_pfnReadMem(thisptr, mem, size, xmlFileNameForLogging, xmlPieceReader);
}

XmlDoc *(__thiscall *g_pfnReadFile)(const XmlReader *, const wchar_t *, XmlPieceReader *);
XmlDoc *thiscall_(ReadFile_hook, const XmlReader *thisptr, const wchar_t *xml, XmlPieceReader *xmlPieceReader)
{
  auto xmlDoc = g_pfnReadFile(thisptr, xml, xmlPieceReader);
  if ( !xmlDoc )
    return nullptr;

  auto patches = get_relevant_patches(xml);
  if ( !patches.empty() ) {
    pugi::xml_document doc;
    if ( const auto res = convert_document(doc, xmlDoc) ) {
      apply_patches(doc, res.encoding, patches);
      xml_buffer_writer writer;
      doc.save(writer, nullptr, pugi::format_raw | pugi::format_no_declaration, res.encoding);
      return g_pfnReadMem(thisptr, writer.result.data(), SafeInt(writer.result.size()), xml, xmlPieceReader);
    }
  }
  return xmlDoc;
}
