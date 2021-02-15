#include "pch.h"
#include "xmlcommon.h"
#include "xmlreader.h"

pugi::xml_node convert_append_child(pugi::xml_node &parent, const XmlNode *node)
{
  if ( node ) {
    pugi::xml_node n;
    switch ( node->Type() ) {
      case XmlNode::XML_ELEMENT: {
        const auto el = node->ToXmlElement();
        n = parent.append_child(el->Name());
        for ( int i = 0; i < el->AttributeCount(); ++i )
          n.append_attribute(el->AttributeName(i)) = el->Attribute(i);
        break;
      }
      case XmlNode::XML_TEXT: {
        const auto txt = node->ToXmlTextNode();
        n = parent.append_child(pugi::node_pcdata);
        n.set_value(txt->Value());
        break;
      }
    }
    for ( int i = 0; i < node->ChildCount(); ++i )
      convert_append_child(n, node->Child(i));
    return n;
  }
  return {};
}

pugi::xml_parse_result convert_document(pugi::xml_document &doc, XmlDoc *xmlDoc)
{
  if ( !xmlDoc ) return {};

  auto decl = doc.prepend_child(pugi::node_declaration);
  decl.append_attribute(L"version") = L"1.0";
  decl.append_attribute(L"encoding") = L"utf-16";
  doc.append_child(pugi::node_pcdata).set_value(L"\n");
  doc.append_child(pugi::node_comment).set_value(xmlDoc->Name());
  doc.append_child(pugi::node_pcdata).set_value(L"\n");
  convert_append_child(doc, xmlDoc->Root()->ToXmlNode());

  pugi::xml_parse_result res;
  res.status = pugi::status_ok;
  res.encoding = pugi::encoding_utf16_le;
  return res;
}
