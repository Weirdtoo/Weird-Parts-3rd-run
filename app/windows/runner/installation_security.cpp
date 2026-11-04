#include "installation_security.h"

#include <windows.h>
#include <wincred.h>
#include <sddl.h>

#include <flutter/encodable_value.h>
#include <flutter/method_channel.h>
#include <flutter/standard_method_codec.h>

#include <algorithm>
#include <filesystem>
#include <memory>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

namespace {
constexpr size_t kMaximumPayload = 2048;
constexpr size_t kMaximumRecoveryFile = 65536;
constexpr char kHeader[] = "WPIS1";
constexpr size_t kHeaderSize = 5 + 36;
using Value = flutter::EncodableValue;
using Map = flutter::EncodableMap;

struct Failure : std::runtime_error {
  explicit Failure(const char* value) : std::runtime_error(value) {}
};

bool IsUuid(const std::string& value) {
  if (value.size() != 36) return false;
  for (size_t index = 0; index < value.size(); ++index) {
    if (index == 8 || index == 13 || index == 18 || index == 23) {
      if (value[index] != '-') return false;
    } else if (!((value[index] >= '0' && value[index] <= '9') ||
                 (value[index] >= 'a' && value[index] <= 'f'))) {
      return false;
    }
  }
  return true;
}

const Value* Find(const Map& map, const char* key) {
  const auto item = map.find(Value(key));
  return item == map.end() ? nullptr : &item->second;
}

std::string RequiredString(const Map& map, const char* key) {
  const auto* value = Find(map, key);
  const auto* text = value == nullptr ? nullptr : std::get_if<std::string>(value);
  if (text == nullptr) throw Failure("installation_invalid_argument");
  return *text;
}

bool IsCompanyUserNamespace(const std::string& value) {
  constexpr size_t kMaximumCompanyUsers = 2;
  const std::string prefix = "production.company-user-";
  if (value.rfind(prefix, 0) != 0 || value.size() <= prefix.size() ||
      value[prefix.size()] == '0') return false;
  size_t slot = 0;
  for (size_t i = prefix.size(); i < value.size(); ++i) {
    const char digit = value[i];
    if (digit < '0' || digit > '9') return false;
    slot = slot * 10 + static_cast<size_t>(digit - '0');
    if (slot > kMaximumCompanyUsers) return false;
  }
  return slot >= 1;
}

std::string Namespace(const Map& map) {
  auto value = RequiredString(map, "namespace");
  if (value.empty() || value.size() > 64) throw Failure("installation_invalid_argument");
  for (char c : value) {
    if (!((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') ||
          c == '.' || c == '_' || c == '-')) throw Failure("installation_invalid_argument");
  }
  if (value != "production" && value != "production.company-custody" &&
      !IsCompanyUserNamespace(value)) {
    if (value.rfind("synthetic.", 0) != 0 || value.size() <= 10 ||
        !((value[10] >= 'a' && value[10] <= 'z') ||
          (value[10] >= '0' && value[10] <= '9'))) throw Failure("installation_invalid_argument");
  }
  return value;
}

std::wstring UserSid() {
  HANDLE token = nullptr;
  if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) throw Failure("installation_unavailable");
  DWORD length = 0;
  GetTokenInformation(token, TokenUser, nullptr, 0, &length);
  std::vector<unsigned char> buffer(length);
  const BOOL read = GetTokenInformation(token, TokenUser, buffer.data(), length, &length);
  CloseHandle(token);
  if (!read) throw Failure("installation_unavailable");
  LPWSTR text = nullptr;
  const auto* user = reinterpret_cast<const TOKEN_USER*>(buffer.data());
  if (!ConvertSidToStringSidW(user->User.Sid, &text)) throw Failure("installation_unavailable");
  std::wstring result(text);
  LocalFree(text);
  return result;
}

class NamespaceLock {
 public:
  NamespaceLock(const std::wstring& sid, const std::wstring& scope) {
    const auto sddl = L"D:P(A;;GA;;;" + sid + L")";
    PSECURITY_DESCRIPTOR descriptor = nullptr;
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl.c_str(), SDDL_REVISION_1, &descriptor, nullptr)) throw Failure("installation_unavailable");
    SECURITY_ATTRIBUTES attributes{sizeof(SECURITY_ATTRIBUTES), descriptor, FALSE};
    const auto name = L"Global\\WiredParts.Installation.v1." + sid + L"." + scope;
    handle_ = CreateMutexW(&attributes, FALSE, name.c_str());
    LocalFree(descriptor);
    if (handle_ == nullptr) throw Failure("installation_unavailable");
    const DWORD result = WaitForSingleObject(handle_, 10000);
    if (result != WAIT_OBJECT_0 && result != WAIT_ABANDONED) {
      CloseHandle(handle_);
      handle_ = nullptr;
      throw Failure("installation_busy");
    }
  }
  ~NamespaceLock() {
    if (handle_ != nullptr) {
      ReleaseMutex(handle_);
      CloseHandle(handle_);
    }
  }
  NamespaceLock(const NamespaceLock&) = delete;
  NamespaceLock& operator=(const NamespaceLock&) = delete;
 private:
  HANDLE handle_ = nullptr;
};

struct Record {
  bool exists = false;
  std::string revision;
  std::vector<uint8_t> bytes;
};

Record Read(const std::wstring& target) {
  PCREDENTIALW credential = nullptr;
  if (!CredReadW(target.c_str(), CRED_TYPE_GENERIC, 0, &credential)) {
    if (GetLastError() == ERROR_NOT_FOUND) return {};
    throw Failure("installation_unavailable");
  }
  const auto release = [](CREDENTIALW* value) { CredFree(value); };
  std::unique_ptr<CREDENTIALW, decltype(release)> owned(credential, release);
  if (credential->Persist != CRED_PERSIST_LOCAL_MACHINE ||
      credential->CredentialBlobSize < kHeaderSize ||
      credential->CredentialBlobSize > kHeaderSize + kMaximumPayload ||
      credential->CredentialBlob == nullptr ||
      !std::equal(kHeader, kHeader + 5, credential->CredentialBlob)) throw Failure("installation_corrupt");
  Record record;
  record.exists = true;
  record.revision.assign(reinterpret_cast<const char*>(credential->CredentialBlob + 5), 36);
  if (!IsUuid(record.revision)) throw Failure("installation_corrupt");
  record.bytes.assign(credential->CredentialBlob + kHeaderSize,
                      credential->CredentialBlob + credential->CredentialBlobSize);
  return record;
}

void Write(const std::wstring& target, const std::wstring& sid,
           const std::string& revision, const std::vector<uint8_t>& bytes) {
  std::vector<uint8_t> wrapped(kHeader, kHeader + 5);
  wrapped.insert(wrapped.end(), revision.begin(), revision.end());
  wrapped.insert(wrapped.end(), bytes.begin(), bytes.end());
  CREDENTIALW credential{};
  credential.Type = CRED_TYPE_GENERIC;
  credential.TargetName = const_cast<LPWSTR>(target.c_str());
  credential.Persist = CRED_PERSIST_LOCAL_MACHINE;
  credential.UserName = const_cast<LPWSTR>(sid.c_str());
  credential.CredentialBlobSize = static_cast<DWORD>(wrapped.size());
  credential.CredentialBlob = wrapped.data();
  const BOOL saved = CredWriteW(&credential, 0);
  SecureZeroMemory(wrapped.data(), wrapped.size());
  if (!saved) throw Failure("installation_unavailable");
}

std::wstring AbsoluteRecoveryPath(const Map& arguments) {
  const auto utf8_path = RequiredString(arguments, "path");
  if (utf8_path.empty() || utf8_path.size() > 32767 ||
      utf8_path.find('\0') != std::string::npos) throw Failure("installation_invalid_argument");
  const int length = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS,
                                       utf8_path.data(), static_cast<int>(utf8_path.size()), nullptr, 0);
  if (length <= 0) throw Failure("installation_invalid_argument");
  std::wstring path(length, L'\0');
  if (MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, utf8_path.data(),
                          static_cast<int>(utf8_path.size()), path.data(), length) != length ||
      !std::filesystem::path(path).is_absolute() ||
      path.rfind(L"\\\\.\\", 0) == 0 || path.rfind(L"\\\\?\\", 0) == 0) {
    throw Failure("installation_invalid_argument");
  }
  const auto first_colon = path.find(L':');
  if (first_colon != std::wstring::npos && first_colon != 1) throw Failure("installation_invalid_argument");
  if (path.find(L':', first_colon == std::wstring::npos ? 0 : first_colon + 1) !=
      std::wstring::npos) throw Failure("installation_invalid_argument");
  return path;
}

void WriteRecoveryFileExclusive(const Map& arguments) {
  const auto path = AbsoluteRecoveryPath(arguments);
  const auto* value = Find(arguments, "bytes");
  const auto* bytes = value == nullptr ? nullptr : std::get_if<std::vector<uint8_t>>(value);
  if (bytes == nullptr || bytes->empty() || bytes->size() > kMaximumRecoveryFile) {
    throw Failure("installation_invalid_argument");
  }
  HANDLE file = CreateFileW(path.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_NEW,
                            FILE_ATTRIBUTE_NORMAL | FILE_FLAG_WRITE_THROUGH, nullptr);
  if (file == INVALID_HANDLE_VALUE) {
    if (GetLastError() == ERROR_FILE_EXISTS || GetLastError() == ERROR_ALREADY_EXISTS) {
      throw Failure("installation_file_exists");
    }
    throw Failure("installation_unavailable");
  }
  try {
    BY_HANDLE_FILE_INFORMATION info{};
    if (GetFileType(file) != FILE_TYPE_DISK || !GetFileInformationByHandle(file, &info) ||
        (info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0 || info.nNumberOfLinks != 1) {
      throw Failure("installation_unavailable");
    }
    size_t offset = 0;
    while (offset < bytes->size()) {
      DWORD written = 0;
      if (!WriteFile(file, bytes->data() + offset,
                     static_cast<DWORD>(bytes->size() - offset), &written, nullptr) || written == 0) {
        throw Failure("installation_unavailable");
      }
      offset += written;
    }
    if (!FlushFileBuffers(file)) throw Failure("installation_unavailable");
  } catch (...) {
    CloseHandle(file);
    throw;
  }
  CloseHandle(file);
}
}  // namespace

void RegisterInstallationSecurity(flutter::BinaryMessenger* messenger) {
  flutter::MethodChannel<Value> channel(messenger, "wired_parts/installation_security",
                                       &flutter::StandardMethodCodec::GetInstance());
  channel.SetMethodCallHandler([](const flutter::MethodCall<Value>& call,
                                 std::unique_ptr<flutter::MethodResult<Value>> result) {
    try {
      if (call.method_name() != "readState" && call.method_name() != "compareAndSwapState" &&
          call.method_name() != "writeRecoveryFileExclusive") {
        result->NotImplemented();
        return;
      }
      const auto* arguments = call.arguments() == nullptr ? nullptr : std::get_if<Map>(call.arguments());
      if (arguments == nullptr) throw Failure("installation_invalid_argument");
      if (call.method_name() == "writeRecoveryFileExclusive") {
        WriteRecoveryFileExclusive(*arguments);
        const auto* bytes = std::get_if<std::vector<uint8_t>>(Find(*arguments, "bytes"));
        result->Success(Value(Map{{Value("written"), Value(static_cast<int>(bytes->size()))}}));
        return;
      }
      const auto scope = Namespace(*arguments);
      const std::wstring wide_scope(scope.begin(), scope.end());
      const auto sid = UserSid();
      NamespaceLock lock(sid, wide_scope);
      const auto target = L"WiredParts.Installation.v1." + wide_scope;
      const auto current = Read(target);
      if (call.method_name() == "readState") {
        if (!current.exists) result->Success(Value());
        else result->Success(Value(Map{{Value("revision"), Value(current.revision)}, {Value("bytes"), Value(current.bytes)}}));
        return;
      }
      const auto revision = RequiredString(*arguments, "nextRevision");
      if (!IsUuid(revision)) throw Failure("installation_invalid_argument");
      const auto* expected_value = Find(*arguments, "expectedRevision");
      if (expected_value == nullptr) throw Failure("installation_invalid_argument");
      const auto* expected = std::get_if<std::string>(expected_value);
      if (expected == nullptr && !std::holds_alternative<std::monostate>(*expected_value)) throw Failure("installation_invalid_argument");
      if (expected != nullptr && !IsUuid(*expected)) throw Failure("installation_invalid_argument");
      const auto* payload_value = Find(*arguments, "bytes");
      const auto* payload = payload_value == nullptr ? nullptr : std::get_if<std::vector<uint8_t>>(payload_value);
      if (payload == nullptr) throw Failure("installation_invalid_argument");
      if (payload->size() > kMaximumPayload) throw Failure("installation_capacity");
      if (current.exists && current.revision == revision) {
        if (current.bytes != *payload) throw Failure("installation_integrity");
      } else {
        if ((current.exists && (expected == nullptr || *expected != current.revision)) ||
            (!current.exists && expected != nullptr)) throw Failure("installation_conflict");
        Write(target, sid, revision, *payload);
      }
      result->Success(Value(Map{{Value("revision"), Value(revision)}}));
    } catch (const Failure& error) {
      result->Error(error.what(), "Installation security operation failed");
    } catch (...) {
      result->Error("installation_unavailable", "Installation security operation failed");
    }
  });
}
