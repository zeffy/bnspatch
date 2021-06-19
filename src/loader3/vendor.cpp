#include "pch.h"

typedef struct tagLANGANDCODEPAGE
{
  WORD wLanguage;
  WORD wCodePage;
} LANGANDCODEPAGE, *PLANGANDCODEPAGE;

bool IsVendorModule(PUNICODE_STRING Filename)
{
  const std::filesystem::path wstrFilename{static_cast<nt::rtl::unicode_string_view *>(Filename)->wstring()};
  const auto parentPath = wstrFilename.parent_path();

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
    L"NCSOFT",
    L"Tencent",
    L"Innova",
    L"Garena",
    L"INCA Internet",
    L"Wellbia.com"
    L"TGuard"
  };

  for ( UINT i = 0; i < (cbVerInfo / sizeof(LANGANDCODEPAGE)); i++ ) {
    auto wszQueryString = std::format(L"\\StringFileInfo\\{:04x}{:04x}\\CompanyName",
      plc[i].wLanguage, plc[i].wCodePage);

    LPWSTR pwszCompanyName;
    UINT uLen;
    if ( VerQueryValueW(FileVersionInformation.data(), wszQueryString.c_str(), &(LPVOID &)pwszCompanyName, &uLen) ) {
      if ( StrStrNIW(pwszCompanyName, L"Microsoft", uLen) ) {
        wszQueryString = std::format(L"\\StringFileInfo\\{:04x}{:04x}\\ProductName", plc[i].wLanguage, plc[i].wCodePage);
        LPWSTR pwszProductName;
        if ( VerQueryValueW(FileVersionInformation.data(), wszQueryString.c_str(), &(LPVOID &)pwszProductName, &uLen) ) {
          if ( StrStrNIW(pwszProductName, L"Microsoft\xAE Windows\xAE", uLen) )
            return true;
        }
      } else {
        if ( std::ranges::any_of(CompanyNames, std::bind(&StrStrNIW, pwszCompanyName, std::placeholders::_1, uLen)) )
          return true;
      }
    }
  }
  return false;
}
