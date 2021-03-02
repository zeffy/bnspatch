#pragma once

#include "xmlreader.h"

#ifdef _M_X64
#define thiscall_(name, thisarg, ...) name(thisarg, ## __VA_ARGS__) 
#else
#include <cstdint>
#define thiscall_(name, thisarg, ...) __fastcall name(thisarg, intptr_t, ## __VA_ARGS__) 
#endif

extern XmlDoc *(__thiscall *g_pfnReadMem)(const XmlReader *, const unsigned char *, unsigned int, const wchar_t *, XmlPieceReader *);
XmlDoc *thiscall_(ReadMem_hook, const XmlReader *thisptr, const unsigned char *mem, unsigned int size, const wchar_t *xmlFileNameForLogging, XmlPieceReader *xmlPieceReader);

extern XmlDoc *(__thiscall *g_pfnReadFile)(const XmlReader *, const wchar_t *, XmlPieceReader *);
XmlDoc *thiscall_(ReadFile_hook, const XmlReader *thisptr, const wchar_t *xml, XmlPieceReader *xmlPieceReader);
