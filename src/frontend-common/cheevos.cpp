#include "cheevos.h"
#include "common/cd_image.h"
#include "common/file_system.h"
#include "common/log.h"
#include "common/md5_digest.h"
#include "common/string.h"
#include "common/string_util.h"
#include "common_host_interface.h"
#include "core/bios.h"
#include "core/bus.h"
#include "core/cpu_core.h"
#include "core/host_display.h"
#include "core/system.h"
#include "fullscreen_ui.h"
#include "http_downloader.h"
#include "imgui_fullscreen.h"
#include "rapidjson/document.h"
#include "rc_url.h"
#include "rcheevos.h"
#include <algorithm>
#include <cstdarg>
#include <functional>
#include <string>
#include <vector>
Log_SetChannel(Cheevos);

namespace Cheevos {

enum : s32
{
  HTTP_OK = FrontendCommon::HTTPDownloader::HTTP_OK
};

static void CheevosEventHandler(const rc_runtime_event_t* runtime_event);
static unsigned CheevosPeek(unsigned address, unsigned num_bytes, void* ud);
static void ActivateLockedAchievements();
static bool ActivateAchievement(Achievement* achievement);
static void DeactivateAchievement(Achievement* achievement);

/// Uses a temporarily (second) CD image to resolve the hash.
static void GameChanged();

bool g_active = false;
u32 g_game_id = 0;

static bool s_logged_in = false;
static CommonHostInterface* s_host_interface;
static rc_runtime_t s_rcheevos_runtime;
static std::unique_ptr<FrontendCommon::HTTPDownloader> s_http_downloader;
static std::string s_username;
static std::string s_login_token;
static std::string s_game_path;
static std::string s_game_hash;
static std::string s_game_title;
static std::string s_game_developer;
static std::string s_game_publisher;
static std::string s_game_release_date;
static std::string s_game_icon;
static std::vector<Achievement> s_achievements;
static u32 s_total_image_downloads;
static u32 s_completed_image_downloads;
static bool s_image_download_progress_active;

static void FormattedError(const char* format, ...)
{
  if (!s_host_interface)
    return;

  std::va_list ap;
  va_start(ap, format);

  SmallString str;
  str.AppendString("Cheevos Error: ");
  str.AppendFormattedStringVA(format, ap);

  va_end(ap);

  s_host_interface->AddOSDMessage(str.GetCharArray(), 10.0f);
  Log_ErrorPrint(str.GetCharArray());
}

static bool ParseResponseJSON(const char* request_type, s32 status_code,
                              const FrontendCommon::HTTPDownloader::Request::Data& data, rapidjson::Document& doc,
                              const char* success_field = "Success")
{
  if (status_code != HTTP_OK || data.empty())
  {
    FormattedError("%s failed: empty response", request_type);
    return false;
  }

  doc.Parse(reinterpret_cast<const char*>(data.data()), data.size());
  if (doc.HasParseError())
  {
    FormattedError("%s failed: parse error at offset %zu: %u", request_type, doc.GetErrorOffset(),
                   static_cast<unsigned>(doc.GetParseError()));
    return false;
  }

  if (success_field && (!doc.HasMember(success_field) || !doc[success_field].GetBool()))
  {
    FormattedError("%s failed: Server returned an error", request_type);
    return false;
  }

  return true;
}

template<typename T>
static std::string GetOptionalString(const T& value, const char* key)
{
  if (!value.HasMember(key) || !value[key].IsString())
    return std::string();

  return value[key].GetString();
}

template<typename T>
static u32 GetOptionalUInt(const T& value, const char* key)
{
  if (!value.HasMember(key) || !value[key].IsUint())
    return 0;

  return value[key].GetUint();
}

static Achievement* GetAchievementByID(u32 id)
{
  for (Achievement& ach : s_achievements)
  {
    if (ach.id == id)
      return &ach;
  }

  return nullptr;
}

static void ClearGameInfo()
{
  while (!s_achievements.empty())
  {
    Achievement& ach = s_achievements.back();
    DeactivateAchievement(&ach);
    s_achievements.pop_back();
  }

  std::string().swap(s_game_path);
  std::string().swap(s_game_hash);
  std::string().swap(s_game_title);
  std::string().swap(s_game_developer);
  std::string().swap(s_game_publisher);
  std::string().swap(s_game_release_date);
  std::string().swap(s_game_icon);
  g_game_id = 0;
}

bool Initialize(CommonHostInterface* hi)
{
  s_http_downloader = FrontendCommon::HTTPDownloader::Create();
  if (!s_http_downloader)
  {
    Log_ErrorPrint("Failed to create HTTP downloader, cannot use cheevos");
    return false;
  }

  s_host_interface = hi;
  g_active = true;
  rc_runtime_init(&s_rcheevos_runtime);

  s_username = hi->GetSettingsInterface()->GetStringValue("Cheevos", "Username");
  s_login_token = hi->GetSettingsInterface()->GetStringValue("Cheevos", "Token");
  s_logged_in = (!s_username.empty() && !s_login_token.empty());
  return true;
}

void Shutdown()
{
  if (!g_active)
    return;

  Assert(!s_image_download_progress_active);

  s_http_downloader->WaitForAllRequests();
  if (s_logged_in)
  {
    // have to wait again because the logout is async
    LogoutAsync();
    s_http_downloader->WaitForAllRequests();
  }

  ClearGameInfo();

  std::string().swap(s_username);
  std::string().swap(s_login_token);
  s_host_interface = nullptr;
  g_active = false;
  rc_runtime_destroy(&s_rcheevos_runtime);

  s_http_downloader.reset();
}

void Update()
{
  s_http_downloader->PollRequests();

  if (HasActiveGame())
    rc_runtime_do_frame(&s_rcheevos_runtime, &CheevosEventHandler, &CheevosPeek, nullptr, nullptr);
}

static void LoginASyncCallback(s32 status_code, const FrontendCommon::HTTPDownloader::Request::Data& data)
{
  rapidjson::Document doc;
  if (!ParseResponseJSON("Login", status_code, data, doc, nullptr))
    return;

  if (!doc["Success"].IsBool() || !doc["Success"].GetBool() || !doc["User"].IsString() || !doc["Token"].IsString())
  {
    FormattedError("Login failed. Please check your user name and password, and try again.");
    return;
  }

  s_username = doc["User"].GetString();
  s_login_token = doc["Token"].GetString();
  // s_score = doc["Score"].GetInt();
  s_logged_in = true;

  s_host_interface->ReportFormattedMessage("Logged into RetroAchievements using username '%s'.", s_username.c_str());

  // save to config
  s_host_interface->GetSettingsInterface()->SetStringValue("Cheevos", "Username", s_username.c_str());
  s_host_interface->GetSettingsInterface()->SetStringValue("Cheevos", "Token", s_login_token.c_str());

  // If we have a game running, set it up.
  if (System::IsValid())
    GameChanged();
}

bool LoginAsync(const char* username, const char* password)
{
  s_http_downloader->WaitForAllRequests();

  if (s_logged_in)
    return false;

  char url[256] = {};
  int res = rc_url_login_with_password(url, sizeof(url), username, password);
  Assert(res == 0);

  s_http_downloader->CreateRequest(url, LoginASyncCallback);
  return true;
}

void LogoutAsync()
{
  s_http_downloader->WaitForAllRequests();
  if (!s_logged_in)
    return;

  ClearGameInfo();

  std::string().swap(s_username);
  std::string().swap(s_login_token);
}

static void UpdateImageDownloadProgress()
{
  static const char* str_id = "cheevo_image_download";

  if (s_completed_image_downloads >= s_total_image_downloads)
  {
    s_completed_image_downloads = 0;
    s_total_image_downloads = 0;

    if (s_image_download_progress_active)
    {
      ImGuiFullscreen::CloseBackgroundProgressDialog(str_id);
      s_image_download_progress_active = false;
    }

    return;
  }

  if (!s_host_interface->IsFullscreenUIEnabled())
    return;

  std::string message("Downloading achievement resources...");
  if (!s_image_download_progress_active)
  {
    ImGuiFullscreen::OpenBackgroundProgressDialog(str_id, std::move(message), 0,
                                                  static_cast<s32>(s_total_image_downloads),
                                                  static_cast<s32>(s_completed_image_downloads));
    s_image_download_progress_active = true;
  }
  else
  {
    ImGuiFullscreen::UpdateBackgroundProgressDialog(str_id, std::move(message), 0,
                                                    static_cast<s32>(s_total_image_downloads),
                                                    static_cast<s32>(s_completed_image_downloads));
  }
}

static void DownloadImage(std::string url, std::string cache_filename)
{
  auto callback = [cache_filename](s32 status_code, const FrontendCommon::HTTPDownloader::Request::Data& data) {
    s_completed_image_downloads++;
    UpdateImageDownloadProgress();

    if (status_code != HTTP_OK)
      return;

    if (!FileSystem::WriteBinaryFile(cache_filename.c_str(), data.data(), data.size()))
    {
      Log_ErrorPrintf("Failed to write badge image to '%s'", cache_filename.c_str());
      return;
    }

    FullscreenUI::InvalidateCachedTexture(cache_filename);
    UpdateImageDownloadProgress();
  };

  s_total_image_downloads++;
  UpdateImageDownloadProgress();

  s_http_downloader->CreateRequest(std::move(url), std::move(callback));
}

static std::string GetBadgeImageFilename(const char* badge_name, bool locked, bool cache_path)
{
  if (!cache_path)
  {
    return StringUtil::StdStringFromFormat("%s%s.png", badge_name, locked ? "_lock" : "");
  }
  else
  {
    // well, this comes from the internet.... :)
    SmallString clean_name(badge_name);
    FileSystem::SanitizeFileName(clean_name);
    return s_host_interface->GetUserDirectoryRelativePath("cache" FS_OSPATH_SEPARATOR_STR
                                                          "achievement_badge" FS_OSPATH_SEPARATOR_STR "%s%s.png",
                                                          clean_name.GetCharArray(), locked ? "_lock" : "");
  }
}

static std::string ResolveBadgePath(const char* badge_name, bool locked)
{
  char url[256];

  // unlocked image
  std::string cache_path(GetBadgeImageFilename(badge_name, locked, true));
  if (FileSystem::FileExists(cache_path.c_str()))
    return cache_path;

  std::string badge_name_with_extension(GetBadgeImageFilename(badge_name, locked, false));
  int res = rc_url_get_badge_image(url, sizeof(url), badge_name_with_extension.c_str());
  Assert(res == 0);
  DownloadImage(url, cache_path);
  return cache_path;
}

static void GetUserUnlocksCallback(s32 status_code, const FrontendCommon::HTTPDownloader::Request::Data& data)
{
  rapidjson::Document doc;
  if (!ParseResponseJSON("Get User Unlocks", status_code, data, doc))
  {
    ClearGameInfo();
    return;
  }

  // verify game id for sanity
  const u32 game_id = GetOptionalUInt(doc, "GameID");
  if (game_id != g_game_id)
  {
    FormattedError("GameID from user unlocks doesn't match (got %u expected %u)", game_id, g_game_id);
    ClearGameInfo();
    return;
  }

  // flag achievements as unlocked
  if (doc.HasMember("UserUnlocks") && doc["UserUnlocks"].IsArray())
  {
    for (const auto& value : doc["UserUnlocks"].GetArray())
    {
      if (!value.IsUint())
        continue;

      const u32 achievement_id = value.GetUint();
      Achievement* cheevo = GetAchievementByID(achievement_id);
      if (!cheevo)
      {
        Log_ErrorPrintf("Server returned unknown achievement %u", achievement_id);
        continue;
      }

      cheevo->locked = false;
    }
  }

  // start scanning for locked achievements
  ActivateLockedAchievements();

  std::string title(StringUtil::StdStringFromFormat("%s (%s)", s_game_title.c_str(), s_game_developer.c_str()));
  std::string summary(StringUtil::StdStringFromFormat("You have earned %u of %u achievements, and %u of %u points.",
                                                      GetUnlockedAchiementCount(), GetAchievementCount(),
                                                      GetCurrentPointsForGame(), GetMaximumPointsForGame()));
  ImGuiFullscreen::AddNotification(10.0f, std::move(title), std::move(summary), s_game_icon);
}

static void GetUserUnlocks()
{
  char url[256];
  int res = rc_url_get_unlock_list(url, sizeof(url), s_username.c_str(), s_login_token.c_str(), g_game_id, 0);
  Assert(res == 0);

  s_http_downloader->CreateRequest(url, GetUserUnlocksCallback);
}

static void GetPatchesCallback(s32 status_code, const FrontendCommon::HTTPDownloader::Request::Data& data)
{
  rapidjson::Document doc;
  if (!ParseResponseJSON("Get Patches", status_code, data, doc))
    return;

  if (!doc.HasMember("PatchData"))
  {
    FormattedError("No patch data returned from server.");
    return;
  }

  // parse info
  const auto patch_data(doc["PatchData"].GetObject());
  s_game_title = GetOptionalString(patch_data, "Title");
  s_game_developer = GetOptionalString(patch_data, "Developer");
  s_game_publisher = GetOptionalString(patch_data, "Publisher");
  s_game_release_date = GetOptionalString(patch_data, "Released");

  // try for a icon
  std::string icon_name(GetOptionalString(patch_data, "ImageIcon"));
  if (!icon_name.empty())
  {
    s_game_icon = s_host_interface->GetUserDirectoryRelativePath(
      "cache" FS_OSPATH_SEPARATOR_STR "achievement_gameicon" FS_OSPATH_SEPARATOR_STR "%u.png", g_game_id);
    if (!FileSystem::FileExists(s_game_icon.c_str()))
    {
      // for some reason rurl doesn't have this :(
      std::string icon_url(StringUtil::StdStringFromFormat("http://i.retroachievements.org%s", icon_name.c_str()));
      DownloadImage(std::move(icon_url), s_game_icon);
    }
  }

  // parse achievements
  if (patch_data.HasMember("Achievements") && patch_data["Achievements"].IsArray())
  {
    const auto achievements(patch_data["Achievements"].GetArray());
    for (const auto& achievement : achievements)
    {
      if (!achievement.HasMember("ID") || !achievement["ID"].IsNumber() || !achievement.HasMember("MemAddr") ||
          !achievement["MemAddr"].IsString() || !achievement.HasMember("Title") || !achievement["Title"].IsString())
      {
        continue;
      }

      const u32 id = achievement["ID"].GetUint();
      const char* memaddr = achievement["MemAddr"].GetString();
      std::string title = achievement["Title"].GetString();
      std::string description = GetOptionalString(achievement, "Description");
      std::string badge_name = GetOptionalString(achievement, "BadgeName");
      const u32 points = GetOptionalUInt(achievement, "Points");

      if (GetAchievementByID(id))
      {
        Log_ErrorPrintf("Achievement %u already exists", id);
        continue;
      }

      Achievement achievement;
      achievement.id = id;
      achievement.memaddr = memaddr;
      achievement.title = std::move(title);
      achievement.description = std::move(description);
      achievement.locked = true;
      achievement.active = false;
      achievement.points = points;

      if (!badge_name.empty())
      {
        achievement.locked_badge_path = ResolveBadgePath(badge_name.c_str(), true);
        achievement.unlocked_badge_path = ResolveBadgePath(badge_name.c_str(), false);
      }

      s_achievements.push_back(std::move(achievement));
    }
  }

  Log_InfoPrintf("Game Title: %s", s_game_title.c_str());
  Log_InfoPrintf("Game Developer: %s", s_game_developer.c_str());
  Log_InfoPrintf("Game Publisher: %s", s_game_publisher.c_str());
  Log_InfoPrintf("Achievements: %u", s_achievements.size());

  if (!s_achievements.empty())
  {
    GetUserUnlocks();
  }
  else
  {
    s_host_interface->AddFormattedOSDMessage(10.0f, "Game '%s' has no achievements.", s_game_title.c_str());
    return;
  }
}

static void GetPatches()
{
#if 1
  char url[256] = {};
  int res = rc_url_get_patch(url, sizeof(url), s_username.c_str(), s_login_token.c_str(), g_game_id);
  Assert(res == 0);

  s_http_downloader->CreateRequest(url, GetPatchesCallback);
#else
  std::optional<std::vector<u8>> f = FileSystem::ReadBinaryFile("D:\\10434.txt");
  if (!f)
    return;

  GetPatchesCallback(200, *f);
#endif
}

static std::string GetGameHash(CDImage* cdi)
{
  std::string executable_name;
  std::vector<u8> executable_data;
  if (!System::ReadExecutableFromImage(cdi, &executable_name, &executable_data))
    return {};

  BIOS::PSEXEHeader header;
  if (executable_data.size() >= sizeof(header))
    std::memcpy(&header, executable_data.data(), sizeof(header));
  if (!BIOS::IsValidPSExeHeader(header, static_cast<u32>(executable_data.size())))
  {
    Log_ErrorPrintf("PS-EXE header is invalid in '%s' (%zu bytes)", executable_name.c_str(), executable_data.size());
    return {};
  }

  // See rcheevos hash.c - rc_hash_psx().
  const u32 MAX_HASH_SIZE = 64 * 1024 * 1024;
  const u32 hash_size = std::min<u32>(sizeof(header) + header.file_size, MAX_HASH_SIZE);
  Assert(hash_size <= executable_data.size());

  MD5Digest digest;
  digest.Update(executable_name.c_str(), static_cast<u32>(executable_name.size()));
  if (hash_size > 0)
    digest.Update(executable_data.data(), hash_size);

  u8 hash[16];
  digest.Final(hash);

  std::string hash_str(StringUtil::StdStringFromFormat(
    "%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x", hash[0], hash[1], hash[2], hash[3], hash[4],
    hash[5], hash[6], hash[7], hash[8], hash[9], hash[10], hash[11], hash[12], hash[13], hash[14], hash[15]));

  Log_InfoPrintf("Hash for '%s' (%zu bytes, %u bytes hashed): %s", executable_name.c_str(), executable_data.size(),
                 hash_size, hash_str.c_str());
  return hash_str;
}

static void GetGameIdCallback(s32 status_code, const FrontendCommon::HTTPDownloader::Request::Data& data)
{
  rapidjson::Document doc;
  if (!ParseResponseJSON("Get Game ID", status_code, data, doc))
    return;

  const u32 game_id = (doc.HasMember("GameID") && doc["GameID"].IsUint()) ? doc["GameID"].GetUint() : 0;
  Log_InfoPrintf("Server returned GameID %u", game_id);
  g_game_id = game_id;

  if (g_game_id != 0)
    GetPatches();
}

void GameChanged()
{
  Assert(System::IsValid());
  ClearGameInfo();

  const std::string& path = System::GetRunningCode();
  if (path.empty())
    return;

  std::unique_ptr<CDImage> cdi = CDImage::Open(path.c_str());
  if (!cdi)
  {
    Log_ErrorPrintf("Failed to open temporary CD image '%s'", path.c_str());
    return;
  }

  GameChanged(path, cdi.get());
}

void GameChanged(const std::string& path, CDImage* image)
{
  if (s_game_path == path)
    return;

  s_http_downloader->WaitForAllRequests();

  ClearGameInfo();
  s_game_path = path;
  if (!image)
    return;

#if 1
  s_game_hash = GetGameHash(image);
  if (s_game_hash.empty())
  {
    s_host_interface->AddOSDMessage(
      s_host_interface->TranslateStdString("OSDMessage", "Failed to read executable from disc. Achievements disabled."),
      10.0f);
    return;
  }

  char url[256];
  int res = rc_url_get_gameid(url, sizeof(url), s_game_hash.c_str());
  Assert(res == 0);

  s_http_downloader->CreateRequest(url, GetGameIdCallback);
#else
  g_game_id = 10434;
  GetPatches();
#endif
}

const std::string& GetGameTitle()
{
  return s_game_title;
}

const std::string& GetGameDeveloper()
{
  return s_game_developer;
}

const std::string& GetGamePublisher()
{
  return s_game_publisher;
}

const std::string& GetGameReleaseDate()
{
  return s_game_release_date;
}

const std::string& GetGameIcon()
{
  return s_game_icon;
}

bool EnumerateAchievements(std::function<bool(const Achievement&)> callback)
{
  for (const Achievement& cheevo : s_achievements)
  {
    if (!callback(cheevo))
      return false;
  }

  return true;
}

u32 GetUnlockedAchiementCount()
{
  u32 count = 0;
  for (const Achievement& cheevo : s_achievements)
  {
    if (!cheevo.locked)
      count++;
  }

  return count;
}

u32 GetAchievementCount()
{
  return static_cast<u32>(s_achievements.size());
}

u32 GetMaximumPointsForGame()
{
  u32 points = 0;
  for (const Achievement& cheevo : s_achievements)
    points += cheevo.points;

  return points;
}

u32 GetCurrentPointsForGame()
{
  u32 points = 0;
  for (const Achievement& cheevo : s_achievements)
  {
    if (!cheevo.locked)
      points += cheevo.points;
  }

  return points;
}

void ActivateLockedAchievements()
{
  for (Achievement& cheevo : s_achievements)
  {
    if (cheevo.locked)
      ActivateAchievement(&cheevo);
  }
}

bool ActivateAchievement(Achievement* achievement)
{
  if (achievement->active)
    return true;

  const int err =
    rc_runtime_activate_achievement(&s_rcheevos_runtime, achievement->id, achievement->memaddr.c_str(), nullptr, 0);
  if (err != RC_OK)
  {
    Log_ErrorPrintf("Achievement %u memaddr parse error: %s", achievement->id, rc_error_str(err));
    return false;
  }

  achievement->active = true;

  Log_DevPrintf("Activated achievement %s (%u)", achievement->title.c_str(), achievement->id);
  return true;
}

void DeactivateAchievement(Achievement* achievement)
{
  if (!achievement->active)
    return;

  rc_runtime_deactivate_achievement(&s_rcheevos_runtime, achievement->id);
  achievement->active = false;

  Log_DevPrintf("Deactivated achievement %s (%u)", achievement->title.c_str(), achievement->id);
}

static void UnlockAchievementCallback(s32 status_code, const FrontendCommon::HTTPDownloader::Request::Data& data)
{
  rapidjson::Document doc;
  if (!ParseResponseJSON("Award Cheevo", status_code, data, doc))
    return;

  // we don't really need to do anything here
}

void UnlockAchievement(u32 achievement_id, bool add_notification /* = true*/)
{
  Achievement* achievement = GetAchievementByID(achievement_id);
  if (!achievement)
  {
    Log_ErrorPrintf("Attempting to unlock unknown achievement %u", achievement_id);
    return;
  }
  else if (!achievement->locked)
  {
    Log_WarningPrintf("Achievement %u for game %u is already unlocked", achievement_id, g_game_id);
    return;
  }

  // TODO: Remove memref?
  achievement->locked = false;
  DeactivateAchievement(achievement);

  // TODO: Add points

  Log_InfoPrintf("Achievement %s (%u) for game %u unlocked", achievement->title.c_str(), achievement_id, g_game_id);
  ImGuiFullscreen::AddNotification(15.0f, "Achievement Unlocked!", achievement->title,
                                   achievement->unlocked_badge_path);

  if (g_settings.cheevos_test_mode)
  {
    Log_WarningPrintf("Skipping sending achievement %u unlock to server because of test mode.", achievement_id);
    return;
  }

  char url[256];
  rc_url_award_cheevo(url, sizeof(url), s_username.c_str(), s_login_token.c_str(), achievement_id, 0,
                      s_game_hash.c_str());
  s_http_downloader->CreateRequest(url, UnlockAchievementCallback);
}

void CheevosEventHandler(const rc_runtime_event_t* runtime_event)
{
  static const char* events[] = {"RC_RUNTIME_EVENT_ACHIEVEMENT_ACTIVATED", "RC_RUNTIME_EVENT_ACHIEVEMENT_PAUSED",
                                 "RC_RUNTIME_EVENT_ACHIEVEMENT_RESET",     "RC_RUNTIME_EVENT_ACHIEVEMENT_TRIGGERED",
                                 "RC_RUNTIME_EVENT_ACHIEVEMENT_PRIMED",    "RC_RUNTIME_EVENT_LBOARD_STARTED",
                                 "RC_RUNTIME_EVENT_LBOARD_CANCELED",       "RC_RUNTIME_EVENT_LBOARD_UPDATED",
                                 "RC_RUNTIME_EVENT_LBOARD_TRIGGERED",      "RC_RUNTIME_EVENT_ACHIEVEMENT_DISABLED",
                                 "RC_RUNTIME_EVENT_LBOARD_DISABLED"};
  const char* event_text =
    ((unsigned)runtime_event->type >= countof(events)) ? "unknown" : events[(unsigned)runtime_event->type];
  Log_DevPrintf("Cheevos Event %s for %u", event_text, runtime_event->id);

  if (runtime_event->type == RC_RUNTIME_EVENT_ACHIEVEMENT_TRIGGERED)
    UnlockAchievement(runtime_event->id);
}

// from cheats.cpp - do we want to move this somewhere else?
template<typename T>
static T DoMemoryRead(PhysicalMemoryAddress address)
{
  T result;

  if ((address & CPU::DCACHE_LOCATION_MASK) == CPU::DCACHE_LOCATION &&
      (address & CPU::DCACHE_OFFSET_MASK) < CPU::DCACHE_SIZE)
  {
    std::memcpy(&result, &CPU::g_state.dcache[address & CPU::DCACHE_OFFSET_MASK], sizeof(result));
    return result;
  }

  address &= CPU::PHYSICAL_MEMORY_ADDRESS_MASK;

  if (address < Bus::RAM_MIRROR_END)
  {
    std::memcpy(&result, &Bus::g_ram[address & Bus::RAM_MASK], sizeof(result));
    return result;
  }

  if (address >= Bus::BIOS_BASE && address < (Bus::BIOS_BASE + Bus::BIOS_SIZE))
  {
    std::memcpy(&result, &Bus::g_bios[address & Bus::BIOS_MASK], sizeof(result));
    return result;
  }

  result = static_cast<T>(0);
  return result;
}

unsigned CheevosPeek(unsigned address, unsigned num_bytes, void* ud)
{
  switch (num_bytes)
  {
    case 1:
      return ZeroExtend32(DoMemoryRead<u8>(address));
    case 2:
      return ZeroExtend32(DoMemoryRead<u16>(address));
    case 4:
      return ZeroExtend32(DoMemoryRead<u32>(address));
    default:
      return 0;
  }
}

} // namespace Cheevos