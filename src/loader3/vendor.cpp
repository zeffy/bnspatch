#include "pch.h"

typedef struct tagLANGANDCODEPAGE
{
  WORD wLanguage;
  WORD wCodePage;
} LANGANDCODEPAGE, *PLANGANDCODEPAGE;

bool IsVendorModule(const nt::rtl::unicode_string_view &Filename)
{
  const auto wstrFilename = Filename.wstring();

  DWORD dwHandle;
  const auto dwLen = GetFileVersionInfoSizeExW(0, wstrFilename.c_str(), &dwHandle);
  if ( !dwLen )
    return false;

  std::vector<UCHAR> FileVersionInformation(dwLen);
  if ( !GetFileVersionInfoExW(FILE_VER_GET_PREFETCHED, wstrFilename.c_str(), 0, dwLen, FileVersionInformation.data()) )
    return false;

  PLANGANDCODEPAGE plc;
  UINT cbVerInfo;

  if ( !VerQueryValueW(FileVersionInformation.data(), L"\\VarFileInfo\\Translation", (LPVOID *)&plc, &cbVerInfo) )
    return false;

  constexpr std::array CompanyNames{
    L"Microsoft",
    L"NCSOFT",
    L"Tencent",
    L"Innova",
    L"Garena",
    L"INCA Internet",
    L"Wellbia.com"
    L"TGuard"
  };
  for ( UINT i = 0; i < (cbVerInfo / sizeof(LANGANDCODEPAGE)); i++ ) {
    const auto wszQueryString = std::format(L"\\StringFileInfo\\{:04x}{:04x}\\ProductName",
      plc[i].wLanguage, plc[i].wCodePage);

    LPCWSTR pwszCompanyName;
    UINT uLen;
    if ( VerQueryValueW(FileVersionInformation.data(), wszQueryString.c_str(), (LPVOID *)&pwszCompanyName, &uLen)
      && std::ranges::any_of(CompanyNames, std::bind(&StrStrNIW, std::placeholders::_1, pwszCompanyName, uLen)) )
      return true;
  }
  return false;
}
