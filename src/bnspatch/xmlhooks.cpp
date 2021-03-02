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
      xml_wstring_writer wswriter;

      if ( thisptr->IsBinary(mem, size) ) {
        auto xmlDoc = g_pfnReadMem(thisptr, mem, size, xmlFileNameForLogging, xmlPieceReader);
        if ( !xmlDoc )
          return nullptr;

        res = convert_document(doc, xmlDoc);
        thisptr->Close(xmlDoc);

        if ( !addons.empty() ) {
          // write document preserving whitespace for addon compatibility
          doc.save(wswriter, L"", pugi::format_default | pugi::format_no_declaration, res.encoding);

          // apply addons
          for ( const auto &addon : addons ) {
            const auto &ref = addon.get();
            xml_snr_addon_base::replace_all(wswriter.result, ref.first, ref.second);
          }

          const auto cb = SafeInt(wswriter.result.size() * sizeof(wchar_t));

          if ( patches.empty() )
            return g_pfnReadMem(thisptr, reinterpret_cast<unsigned char *>(wswriter.result.data()), cb, xmlFileNameForLogging, xmlPieceReader);

          // reload document
          res = doc.load_buffer_inplace(wswriter.result.data(), cb, pugi::parse_default | pugi::parse_declaration);
        }
      } else {
        res = doc.load_buffer(mem, size, pugi::parse_default | pugi::parse_declaration);
      }

      if ( res ) {
        //apply patches
        for ( const auto &patch : patches ) {
          std::unordered_map<std::wstring, pugi::xml_node> node_keys;
          patch_node(doc, res.encoding, doc, patch.children(), node_keys);
        }

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

  const auto patches = get_relevant_patches(xml);
  if ( !patches.empty() ) {
    pugi::xml_document doc;
    const auto res = convert_document(doc, xmlDoc);
    thisptr->Close(xmlDoc);
    for ( const auto &patch : patches ) {
      std::unordered_map<std::wstring, pugi::xml_node> node_keys;
      patch_node(doc, res.encoding, doc, patch.children(), node_keys);
    }

    xml_buffer_writer writer;
    doc.save(writer, nullptr, pugi::format_raw | pugi::format_no_declaration, res.encoding);
    return g_pfnReadMem(thisptr, writer.result.data(), SafeInt(writer.result.size()), xml, xmlPieceReader);
  }
  return xmlDoc;
}
