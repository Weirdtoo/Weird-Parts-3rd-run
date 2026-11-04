import Foundation
import Security
import Darwin

enum StoreError: Error {
  case unavailable
  case keychain(OSStatus)
  case operatingSystem(Int32)
  case conflict
  case integrity
  case capacity
  case invalidArgument
  case busy
  case corrupt

  var code: String {
    switch self {
    case .unavailable, .keychain, .operatingSystem: return "installation_unavailable"
    case .conflict: return "installation_conflict"
    case .integrity: return "installation_integrity"
    case .capacity: return "installation_capacity"
    case .invalidArgument: return "installation_invalid_argument"
    case .busy: return "installation_busy"
    case .corrupt: return "installation_corrupt"
    }
  }

  var message: String {
    switch self {
    case .unavailable, .keychain, .operatingSystem: return "Protected installation storage is unavailable."
    case .conflict: return "The installation state changed."
    case .integrity: return "The installation revision has different data."
    case .capacity: return "The installation state exceeds capacity."
    case .invalidArgument: return "Invalid installation storage arguments."
    case .busy: return "Protected installation storage is busy."
    case .corrupt: return "Protected installation state is malformed."
    }
  }

  var details: [String: Int32]? {
    switch self {
    case .keychain(let status): return ["osStatus": status]
    case .operatingSystem(let number): return ["errno": number]
    default: return nil
    }
  }
}

struct InstallationSecurityNamespace {
  private static let maximumCompanyUsers = 2
  let rawValue: String

  init(_ rawValue: String) throws {
    let bytes = Array(rawValue.utf8)
    guard !bytes.isEmpty, bytes.count <= 64,
      bytes.allSatisfy({ Self.isAlphanumeric($0) || $0 == 46 || $0 == 95 || $0 == 45 }) else {
      throw StoreError.invalidArgument
    }
    if rawValue != "production" && rawValue != "production.company-custody"
      && !Self.isCompanyUserNamespace(rawValue) {
      let prefix = "synthetic."
      guard rawValue.hasPrefix(prefix),
        let first = bytes.dropFirst(prefix.utf8.count).first,
        Self.isAlphanumeric(first) else {
        throw StoreError.invalidArgument
      }
    }
    self.rawValue = rawValue
  }

  private static func isCompanyUserNamespace(_ value: String) -> Bool {
    let prefix = "production.company-user-"
    guard value.hasPrefix(prefix) else { return false }
    let suffix = String(value.dropFirst(prefix.count))
    guard let slot = Int(suffix), (1...maximumCompanyUsers).contains(slot) else {
      return false
    }
    return suffix == String(slot)
  }

  private static func isAlphanumeric(_ byte: UInt8) -> Bool {
    (byte >= 97 && byte <= 122) || (byte >= 48 && byte <= 57)
  }
}

struct InstallationSecurityRevision: Equatable {
  let uuid: UUID
  var rawValue: String { uuid.uuidString.lowercased() }

  init(_ rawValue: String) throws {
    guard let uuid = UUID(uuidString: rawValue), uuid.uuidString.lowercased() == rawValue else {
      throw StoreError.invalidArgument
    }
    self.uuid = uuid
  }

  fileprivate init(uuid: UUID) {
    self.uuid = uuid
  }
}

struct ProtectedInstallationState {
  let revision: InstallationSecurityRevision
  let bytes: Data

  init(revision: InstallationSecurityRevision, bytes: Data) throws {
    guard bytes.count <= InstallationSecurityRecordCodec.maximumPayloadBytes else {
      throw StoreError.capacity
    }
    self.revision = revision
    self.bytes = bytes
  }
}

enum InstallationSecurityRecordCodec {
  static let maximumPayloadBytes = 2048
  static let maximumRecordBytes = 2560
  private static let magic: [UInt8] = [87, 80, 73, 83, 84, 65, 84, 69]
  private static let version: UInt8 = 1
  private static let headerBytes = magic.count + 1 + 16

  static func encode(_ state: ProtectedInstallationState) -> Data {
    var record = Data(magic)
    record.append(version)
    var uuid = state.revision.uuid.uuid
    withUnsafeBytes(of: &uuid) { record.append(contentsOf: $0) }
    record.append(state.bytes)
    return record
  }

  static func decode(_ record: Data) throws -> ProtectedInstallationState {
    guard record.count >= headerBytes,
      record.count <= maximumRecordBytes,
      record.count - headerBytes <= maximumPayloadBytes else {
      throw StoreError.corrupt
    }
    let bytes = Array(record)
    guard Array(bytes.prefix(magic.count)) == magic, bytes[magic.count] == version else {
      throw StoreError.corrupt
    }
    let value = Array(bytes[(magic.count + 1)..<headerBytes])
    let uuid = UUID(uuid: (
      value[0], value[1], value[2], value[3], value[4], value[5], value[6], value[7],
      value[8], value[9], value[10], value[11], value[12], value[13], value[14], value[15]))
    return try ProtectedInstallationState(
      revision: InstallationSecurityRevision(uuid: uuid), bytes: Data(bytes.dropFirst(headerBytes)))
  }
}

enum RecoveryFilePublisher {
  static func writeExclusive(
    path: String,
    bytes: Data,
    synchronizeDirectory: (Int32) -> Int32 = Darwin.fsync,
    fullSynchronizeFile: (Int32) -> Int32 = { Darwin.fcntl($0, F_FULLFSYNC) }
  ) throws -> Int {
    let pathBytes = path.utf8
    guard pathBytes.first == 47, !pathBytes.contains(0), pathBytes.count <= 4096,
      let separator = pathBytes.lastIndex(of: 47),
      !bytes.isEmpty, bytes.count <= 65536 else {
      throw StoreError.invalidArgument
    }
    let parentPath = separator == pathBytes.startIndex
      ? "/" : String(decoding: pathBytes[..<separator], as: UTF8.self)
    let filename = String(decoding: pathBytes[pathBytes.index(after: separator)...], as: UTF8.self)
    let parentDescriptor = open(parentPath, O_RDONLY | O_DIRECTORY | O_CLOEXEC)
    guard parentDescriptor >= 0 else { throw StoreError.operatingSystem(errno) }
    defer { close(parentDescriptor) }
    let descriptor = openat(
      parentDescriptor, filename, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC,
      S_IRUSR | S_IWUSR)
    guard descriptor >= 0 else { throw StoreError.operatingSystem(errno) }
    defer { close(descriptor) }
    var info = stat()
    guard fstat(descriptor, &info) == 0,
      info.st_mode & mode_t(S_IFMT) == mode_t(S_IFREG),
      info.st_uid == geteuid(), info.st_nlink == 1 else {
      throw StoreError.unavailable
    }
    try bytes.withUnsafeBytes { raw in
      guard let base = raw.baseAddress else { throw StoreError.invalidArgument }
      var offset = 0
      while offset < bytes.count {
        let count = Darwin.write(descriptor, base.advanced(by: offset), bytes.count - offset)
        if count < 0 && errno == EINTR { continue }
        guard count > 0 else { throw StoreError.operatingSystem(errno) }
        offset += count
      }
    }
    guard synchronizeDirectory(parentDescriptor) == 0 else {
      throw StoreError.operatingSystem(errno)
    }
    guard fullSynchronizeFile(descriptor) == 0 else {
      throw StoreError.operatingSystem(errno)
    }
    return bytes.count
  }
}

final class InstallationSecurityStore {
  private static let operations = DispatchQueue(label: "wired_parts.installation_security")
  private let service: String
  private let lockDirectory: URL

  init() throws {
    guard let bundleIdentifier = Bundle.main.bundleIdentifier, !bundleIdentifier.isEmpty else {
      throw StoreError.unavailable
    }
    guard let support = FileManager.default.urls(
      for: .applicationSupportDirectory, in: .userDomainMask).first else {
      throw StoreError.unavailable
    }
    service = bundleIdentifier + ".installation_security.v1"
    lockDirectory = support
      .appendingPathComponent(bundleIdentifier, isDirectory: true)
      .appendingPathComponent("installation_security_locks", isDirectory: true)
  }

  func readState(
    namespace: InstallationSecurityNamespace,
    completion: @escaping (Result<ProtectedInstallationState?, StoreError>) -> Void
  ) {
    perform(completion) {
      try self.withNamespaceLock(namespace) { try self.readLocked(namespace) }
    }
  }

  func compareAndSwapState(
    namespace: InstallationSecurityNamespace,
    expectedRevision: InstallationSecurityRevision?,
    nextState: ProtectedInstallationState,
    completion: @escaping (Result<InstallationSecurityRevision, StoreError>) -> Void
  ) {
    perform(completion) {
      try self.withNamespaceLock(namespace) {
        let current = try self.readLocked(namespace)
        if let current = current, current.revision == nextState.revision {
          guard current.bytes == nextState.bytes else { throw StoreError.integrity }
          return current.revision
        }
        guard current?.revision == expectedRevision else { throw StoreError.conflict }
        let record = InstallationSecurityRecordCodec.encode(nextState)
        var attributes: [String: Any] = [
          kSecValueData as String: record,
          kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
        ]
        let status: OSStatus
        if current == nil {
          attributes.merge(self.query(namespace)) { existing, _ in existing }
          status = SecItemAdd(attributes as CFDictionary, nil)
        } else {
          status = SecItemUpdate(self.query(namespace) as CFDictionary, attributes as CFDictionary)
        }
        guard status == errSecSuccess else {
          if status == errSecDuplicateItem || status == errSecItemNotFound {
            throw StoreError.conflict
          }
          throw StoreError.keychain(status)
        }
        return nextState.revision
      }
    }
  }

  func writeRecoveryFileExclusive(
    path: String,
    bytes: Data,
    completion: @escaping (Result<Int, StoreError>) -> Void
  ) {
    perform(completion) {
      try RecoveryFilePublisher.writeExclusive(path: path, bytes: bytes)
    }
  }

  private func perform<Value>(
    _ completion: @escaping (Result<Value, StoreError>) -> Void,
    operation: @escaping () throws -> Value
  ) {
    Self.operations.async {
      let outcome: Result<Value, StoreError>
      do {
        outcome = .success(try operation())
      } catch let error as StoreError {
        outcome = .failure(error)
      } catch {
        outcome = .failure(.unavailable)
      }
      DispatchQueue.main.async { completion(outcome) }
    }
  }

  private func query(_ namespace: InstallationSecurityNamespace) -> [String: Any] {
    [
      kSecClass as String: kSecClassGenericPassword,
      kSecAttrService as String: service,
      kSecAttrAccount as String: namespace.rawValue,
      kSecUseDataProtectionKeychain as String: true,
      kSecAttrSynchronizable as String: false,
      kSecUseAuthenticationUI as String: kSecUseAuthenticationUIFail,
    ]
  }

  private func readLocked(_ namespace: InstallationSecurityNamespace) throws -> ProtectedInstallationState? {
    var request = query(namespace)
    request[kSecMatchLimit as String] = kSecMatchLimitOne
    request[kSecReturnData as String] = true
    request[kSecReturnAttributes as String] = true
    var value: CFTypeRef?
    let status = SecItemCopyMatching(request as CFDictionary, &value)
    if status == errSecItemNotFound { return nil }
    guard status == errSecSuccess else { throw StoreError.keychain(status) }
    guard let item = value as? [String: Any],
      let record = item[kSecValueData as String] as? Data,
      let accessibility = item[kSecAttrAccessible as String] as? String,
      accessibility == (kSecAttrAccessibleWhenUnlockedThisDeviceOnly as String) else {
      throw StoreError.corrupt
    }
    return try InstallationSecurityRecordCodec.decode(record)
  }

  private func withNamespaceLock<Value>(
    _ namespace: InstallationSecurityNamespace, operation: () throws -> Value
  ) throws -> Value {
    do {
      try FileManager.default.createDirectory(
        at: lockDirectory, withIntermediateDirectories: true,
        attributes: [.posixPermissions: 0o700])
    } catch {
      throw StoreError.unavailable
    }
    var directoryInfo = stat()
    guard lstat(lockDirectory.path, &directoryInfo) == 0 else {
      throw StoreError.operatingSystem(errno)
    }
    guard directoryInfo.st_mode & mode_t(S_IFMT) == mode_t(S_IFDIR),
      directoryInfo.st_uid == geteuid() else { throw StoreError.unavailable }
    let path = lockDirectory.appendingPathComponent(namespace.rawValue + ".lock").path
    let descriptor = open(path, O_RDWR | O_CREAT | O_CLOEXEC | O_NOFOLLOW, S_IRUSR | S_IWUSR)
    guard descriptor >= 0 else { throw StoreError.operatingSystem(errno) }
    defer { close(descriptor) }
    var fileInfo = stat()
    guard fstat(descriptor, &fileInfo) == 0 else { throw StoreError.operatingSystem(errno) }
    guard fileInfo.st_mode & mode_t(S_IFMT) == mode_t(S_IFREG),
      fileInfo.st_uid == geteuid(), fileInfo.st_nlink == 1 else { throw StoreError.unavailable }
    guard flock(descriptor, LOCK_EX | LOCK_NB) == 0 else {
      let number = errno
      if number == EWOULDBLOCK || number == EAGAIN { throw StoreError.busy }
      throw StoreError.operatingSystem(number)
    }
    defer { flock(descriptor, LOCK_UN) }
    return try operation()
  }
}
