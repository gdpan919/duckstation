#include "http_downloader_wininet.h"
#include "common/assert.h"
#include "common/log.h"
#include "common/timer.h"
#include <algorithm>
Log_SetChannel(HTTPDownloaderWinInet);

#pragma comment(lib, "WinInet.lib")

namespace FrontendCommon {

HTTPDownloaderWinInet::HTTPDownloaderWinInet() : HTTPDownloader() {}

HTTPDownloaderWinInet::~HTTPDownloaderWinInet()
{
  if (m_hInternet)
    InternetCloseHandle(m_hInternet);
}

std::unique_ptr<HTTPDownloader> HTTPDownloader::Create()
{
  std::unique_ptr<HTTPDownloaderWinInet> instance(std::make_unique<HTTPDownloaderWinInet>());
  if (!instance->Initialize())
    return {};

  return instance;
}

bool HTTPDownloaderWinInet::Initialize()
{
  m_hInternet =
    InternetOpenA(m_user_agent.c_str(), INTERNET_OPEN_TYPE_PRECONFIG, nullptr, nullptr, INTERNET_FLAG_ASYNC);
  if (m_hInternet == NULL)
    return false;

  InternetSetStatusCallback(m_hInternet, HTTPStatusCallback);
  return true;
}

void CALLBACK HTTPDownloaderWinInet::HTTPStatusCallback(HINTERNET hInternet, DWORD_PTR dwContext,
                                                        DWORD dwInternetStatus, LPVOID lpvStatusInformation,
                                                        DWORD dwStatusInformationLength)
{
  Request* req = reinterpret_cast<Request*>(dwContext);
  if (dwInternetStatus == INTERNET_STATUS_HANDLE_CREATED)
  {
    req->hUrl = reinterpret_cast<HINTERNET>(reinterpret_cast<INTERNET_ASYNC_RESULT*>(lpvStatusInformation)->dwResult);
    return;
  }
  else if (dwInternetStatus == INTERNET_STATUS_HANDLE_CLOSING)
  {
    HTTPDownloaderWinInet* parent = static_cast<HTTPDownloaderWinInet*>(req->parent);
    std::unique_lock<std::mutex> lock(parent->m_pending_http_request_lock);
    Assert(std::none_of(parent->m_pending_http_requests.begin(), parent->m_pending_http_requests.end(),
                        [req](HTTPDownloader::Request* it) { return it == req; }));
    delete req;
    return;
  }
  else if (dwInternetStatus != INTERNET_STATUS_REQUEST_COMPLETE)
  {
    return;
  }

  Log_DebugPrintf("Request '%s' complete callback", req->url.c_str());
  Assert(req->state != Request::State::Complete);

  if (req->state == Request::State::Started)
  {
    DWORD buffer_length = sizeof(req->status_code);
    DWORD next_index = 0;
    HttpQueryInfoA(req->hUrl, HTTP_QUERY_STATUS_CODE | HTTP_QUERY_FLAG_NUMBER, &req->status_code, &buffer_length,
                   &next_index);

    if (req->status_code == HTTP_OK)
    {
      req->state = Request::State::Receiving;

      // try for content-length, but it might not exist
      DWORD buffer_length = sizeof(req->content_length);
      DWORD next_index = 0;
      HttpQueryInfoA(req->hUrl, HTTP_QUERY_CONTENT_LENGTH | HTTP_QUERY_FLAG_NUMBER, &req->content_length,
                     &buffer_length, &next_index);
      if (req->content_length > 0)
        req->data.reserve(req->content_length);
    }
  }

  if (req->state == Request::State::Receiving)
  {
    // this is a completed I/O - get the number of bytes written and resize the buffer accordingly
    if (req->io_pending)
    {
      if (!static_cast<BOOL>(reinterpret_cast<INTERNET_ASYNC_RESULT*>(lpvStatusInformation)->dwResult))
      {
        const DWORD error = reinterpret_cast<INTERNET_ASYNC_RESULT*>(lpvStatusInformation)->dwError;
        Log_ErrorPrintf("Async InternetReadFile() returned %u", error);
        req->data.clear();
        req->status_code = -1;
        req->state.store(Request::State::Complete);
        return;
      }

      const u32 new_size = req->io_position + req->io_bytes_read;
      Assert(new_size <= req->data.size());
      req->data.resize(new_size);
      req->io_pending = false;

      if (req->io_bytes_read == 0)
      {
        // end of buffer
        req->state.store(Request::State::Complete);
        return;
      }
    }

    // we need to call InternetReadFile until it returns TRUE and writes zero bytes.
    for (;;)
    {
      const u32 bytes_to_read = (req->content_length > 0) ? (req->content_length - static_cast<u32>(req->data.size())) :
                                                            std::max<u32>(128, static_cast<u32>(req->data.size() * 2));
      if (bytes_to_read == 0)
      {
        req->state.store(Request::State::Complete);
        break;
      }

      req->io_position = static_cast<u32>(req->data.size());
      req->data.resize(req->io_position + bytes_to_read);

      if (InternetReadFile(req->hUrl, &req->data[req->io_position], bytes_to_read, &req->io_bytes_read))
      {
        if (req->io_bytes_read == 0)
        {
          // end of buffer
          req->data.resize(req->io_position);
          req->state.store(Request::State::Complete);
          break;
        }

        req->data.resize(req->io_position + req->io_bytes_read);
      }
      else
      {
        if (GetLastError() == ERROR_IO_PENDING)
        {
          req->io_pending = true;
          return;
        }

        Log_ErrorPrintf("InternetReadFile() error: %u", GetLastError());
        req->status_code = -1;
        req->data.clear();
        req->state.store(Request::State::Complete);
        break;
      }
    }
  }
}

HTTPDownloader::Request* HTTPDownloaderWinInet::InternalCreateRequest()
{
  Request* req = new Request();
  return req;
}

void HTTPDownloaderWinInet::InternalPollRequests()
{
  // noop - it uses windows's worker threads
}

bool HTTPDownloaderWinInet::StartRequest(HTTPDownloader::Request* request)
{
  Request* req = static_cast<Request*>(request);

  req->hUrl = InternetOpenUrlA(m_hInternet, req->url.c_str(), nullptr, 0, INTERNET_FLAG_ASYNC | INTERNET_FLAG_NO_UI,
                               reinterpret_cast<DWORD_PTR>(req));
  if (req->hUrl != NULL || GetLastError() == ERROR_IO_PENDING)
  {
    Log_DevPrintf("Started HTTP request for '%s'", req->url.c_str());
    req->state = Request::State::Started;
    req->start_time = Common::Timer::GetValue();
    return true;
  }

  Log_ErrorPrintf("Failed to start HTTP request for '%s': %u", req->url.c_str(), GetLastError());
  req->callback(-1, req->data);
  delete req;
  return false;
}

void HTTPDownloaderWinInet::CloseRequest(HTTPDownloader::Request* request)
{
  Request* req = static_cast<Request*>(request);

  if (req->hUrl != NULL)
  {
    // req will be freed by the callback.
    // the callback can fire immediately here if there's nothing running async, so don't touch req afterwards
    HINTERNET hUrl = req->hUrl;
    req->hUrl = NULL;
    InternetCloseHandle(hUrl);
  }
  else
  {
    delete req;
  }
}

} // namespace FrontendCommon