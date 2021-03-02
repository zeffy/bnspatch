#pragma once
#include <cstdint>

class XmlReaderIO
{
public:
  enum ErrCode
  {
    ERR_NO_ERROR,
    ERR_UNKNOWN,
    ERR_SYSTEM,
    ERR_NO_MORE_FILE,
    ERR_NOT_IMPLEMENTED,
    ERR_INVALID_PARAM,
    ERR_INSUFFICIENT_BUFFER
  };

  virtual enum ErrCode Open(const wchar_t *path, const wchar_t *xml, bool recursive) = 0;
  virtual enum ErrCode Read(unsigned char *buf, unsigned int *bufsize) const = 0;
  virtual unsigned int GetFileSize() const = 0;
  virtual const wchar_t *GetFileName() const = 0;
  virtual enum ErrCode Next() = 0;
  virtual void Close() = 0;
}; /* size: 0x0008 */

class XmlReaderLog
{
public:
  virtual void Error(const wchar_t *format, ...) const = 0;
  virtual void Debug(const wchar_t *format, ...) const = 0;
  virtual void Trace(const wchar_t *format, ...) const = 0;
}; /* size = 0x0008 */

class XmlDoc
{
public:
  virtual bool IsValid() const = 0;
  virtual const wchar_t *Name() const = 0;
  virtual class XmlElement *Root() = 0;
  virtual int BinarySize() const = 0;
  virtual void SerializeTo(char *buf, int size) const = 0;
  virtual void SerializeFrom(char *buf, int size) = 0;
}; /* size: 0x0008 */

class XmlNode
{
public:
  enum TYPE
  {
    XML_NONE,
    XML_ELEMENT,
    XML_TEXT,
  };

  virtual enum TYPE Type() const = 0;
  virtual bool IsValid() const = 0;
  virtual const wchar_t *Name() const = 0;
  virtual class XmlDoc const *GetDoc() const = 0;
  virtual class XmlNode const *Parent() const = 0;
  virtual int ChildCount() const = 0;
  virtual const class XmlNode *FirstChild() const = 0;
  virtual const class XmlNode *Child(int) const = 0;
  virtual const class XmlNode *Next() const = 0;
  virtual long LineNumber() const = 0;
  virtual const wchar_t *GetURI() const = 0;
  virtual int MemSize() const = 0;
  virtual int Clone(char *buf, int size) const = 0;
  virtual class XmlNode *CloneNode(char *buf, int size) const = 0;
  virtual int BinarySize() const = 0;
  virtual void SerializeTo(char *&buf, int &size) const = 0;
  virtual void SerializeFrom(char *&buf, int &size) = 0;
  virtual const class XmlElement *ToXmlElement() const = 0;
  virtual class XmlElement *ToXmlElement() = 0;
  virtual const class XmlTextNode *ToXmlTextNode() const = 0;
  virtual class XmlTextNode *ToXmlTextNode() = 0;
}; /* size: 0x0008 */

class XmlElement
{
public:
  virtual int ChildElementCount() const = 0;
  virtual const class XmlElement *FirstChildElement() const = 0;
  virtual const class XmlElement *NextElement() const = 0;
  virtual const wchar_t *Name() const = 0;
  virtual long LineNumber() const = 0;
  virtual int AttributeCount() const = 0;
  virtual const wchar_t *Attribute(unsigned int nameHash, const wchar_t *name) const = 0;
  virtual const wchar_t *Attribute(int index) const = 0;
  virtual const wchar_t *Attribute(const wchar_t *name) const = 0;
  virtual const wchar_t *AttributeName(int index) const = 0;
  virtual int AttributeIndex(const wchar_t *name) const = 0;
  virtual const class XmlNode *ToXmlNode() const = 0;
  virtual class XmlNode *ToXmlNode() = 0;
}; /* size: 0x0008 */

class _XmlSaxHandler
{
public:
  virtual bool StartParser() = 0;
  virtual bool EndParser() = 0;
  virtual bool StartElement(class XmlElement *) = 0;
  virtual bool EndElement(class XmlElement *) = 0;
};

#if defined( XMLREADER_INTERFACE_VERSION_13 )

class XmlReader
{
public:
  virtual bool Initialize(class XmlReaderIO *io, const class XmlReaderLog *log, bool useExpat) const = 0;
  virtual const class XmlReaderLog *SetLog(const class XmlReaderLog *log) const = 0;
  virtual const class XmlReaderLog *GetLog() const = 0;
  virtual void Cleanup(bool clearMemory) const = 0;
  virtual class XmlReaderIO *GetIO() const = 0;
  virtual bool Read(const wchar_t *xml, class _XmlSaxHandler &handler) const = 0;
  virtual class XmlDoc *Read(const wchar_t *xml) const = 0;
  virtual class XmlDoc *Read(const unsigned char *mem, unsigned int size, const wchar_t *xmlFileNameForLogging) const = 0;
  virtual void Close(class XmlDoc *doc) const = 0;
  virtual class XmlDoc *NewDoc() const = 0;
  virtual bool IsBinary(const wchar_t *xml) const = 0;
  virtual bool IsBinary(const unsigned char *mem, unsigned int size) const = 0;
}; /* size: 0x0008 */

#else

class XmlPieceReader
{
public:
  virtual bool Read(class XmlDoc *doc) = 0;
  virtual int GetMaxNodeCountPerPiece() = 0;
}; /* size: 0x0008 */

class XmlReader
{
public:
  virtual bool Initialize(class XmlReaderIO *io, const class XmlReaderLog *log, bool useExpat) const = 0;
  virtual const class XmlReaderLog *SetLog(const class XmlReaderLog *) const = 0;
  virtual const class XmlReaderLog *GetLog() const = 0;
  virtual void Cleanup(bool) const = 0;
  virtual class XmlReaderIO *GetIO() const = 0;
  virtual bool Read(const wchar_t *xml, class _XmlSaxHandler &handler) const = 0;
  virtual class XmlDoc *Read(const wchar_t *xml, class XmlPieceReader *xmlPieceReader) const = 0;
  virtual class XmlDoc *Read(const unsigned char *mem, unsigned int size, const wchar_t *xmlFileNameForLogging, class XmlPieceReader *xmlPieceReader) const = 0;
  virtual void Close(class XmlDoc *doc) const = 0;
  virtual class XmlDoc *NewDoc() const = 0;
  virtual bool IsBinary(const unsigned char *mem, unsigned int size) const = 0;
  virtual bool IsBinary(const wchar_t *xml) const = 0;
}; /* size: 0x0008 */

#endif

class XmlTextNode
{
public:
  virtual const wchar_t *Value() const = 0;
  virtual const class XmlNode *ToXmlNode() const = 0;
  virtual class XmlNode *ToXmlNode() = 0;
}; /* size: 0x0008 */
