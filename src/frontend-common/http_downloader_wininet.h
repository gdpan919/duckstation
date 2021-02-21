#pragma once
#include "http_downloader.h"

#include "common/windows_headers.h"

#include <WinInet.h>

namespace FrontendCommon {

class HTTPDownloaderWinInet final : public HTTPDownloader
{
public:
  HTTPDownloaderWinInet();
  ~HTTPDownloaderWinInet() override;

  bool Initialize();

protected:
  Request* InternalCreateRequest() override;
  void InternalPollRequests() override;
  bool StartRequest(HTTPDownloader::Request* request) override;
  void CloseRequest(HTTPDownloader::Request* request) override;

private:
  struct Request : HTTPDownloader::Request
  {
    HINTERNET hUrl = NULL;
    bool io_pending = false;
    u32 io_position = 0;
    DWORD io_bytes_read = 0;
  };

  static void CALLBACK HTTPStatusCallback(HINTERNET hInternet, DWORD_PTR dwContext, DWORD dwInternetStatus,
                                          LPVOID lpvStatusInformation, DWORD dwStatusInformationLength);

  HINTERNET m_hInternet = NULL;
};

} // namespace FrontendCommon