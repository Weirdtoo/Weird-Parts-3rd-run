import Darwin
import Foundation
import XCTest
#if !NATIVE_PUBLISHER_STANDALONE
@testable import wired_parts
#endif

class RunnerTests: XCTestCase {
  #if NATIVE_NETWORK_DIAGNOSTIC_GUARDS
  private func diagnosticArguments() -> [String: Any] {
    ["attempt": "12345678-1234-4234-8234-123456789abc", "run": "g2-users-20261024-pin-a",
      "controller": 2, "generation": 1, "request": 3, "address": "192.168.10.40",
      "port": 6809, "sourceAddress": "192.168.10.20", "interfaceIndex": 7, "prefixLength": 24]
  }

  func testNearbyDiagnosticAcceptedTarget() throws {
    for (source, peer, prefix) in [("192.168.10.20", "192.168.10.40", 24),
      ("10.20.30.40", "10.20.30.41", 24), ("172.16.1.2", "172.16.2.3", 16)] {
      var args = diagnosticArguments()
      args["sourceAddress"] = source
      args["address"] = peer
      args["prefixLength"] = prefix
      let target = try XCTUnwrap(NearbyDiagnosticTarget.parse(args))
      XCTAssertEqual(target.sourceAddress, source)
      XCTAssertEqual(target.address, peer)
      XCTAssertEqual(target.port, 6809)
      XCTAssertEqual(target.interfaceIndex, 7)
      XCTAssertEqual(target.controller, 2)
      XCTAssertEqual(target.generation, 1)
      XCTAssertEqual(target.request, 3)
    }
  }

  func testNearbyDiagnosticUnsafeTarget() {
    for peer in ["example.invalid", "::1", "8.8.8.8", "192.168.11.40", "192.168.10.20",
      "192.168.10.0", "192.168.10.255", "224.0.0.1", "255.255.255.255"] {
      var args = diagnosticArguments()
      args["address"] = peer
      XCTAssertNil(NearbyDiagnosticTarget.parse(args), peer)
    }
    for source in ["8.8.8.8", "127.0.0.1", "192.168.10.0", "192.168.10.255"] {
      var args = diagnosticArguments()
      args["sourceAddress"] = source
      XCTAssertNil(NearbyDiagnosticTarget.parse(args), source)
    }
  }

  func testNearbyDiagnosticPrefixMasks() {
    for prefix in 1...30 {
      XCTAssertEqual(NearbyDiagnosticTarget.prefixLength(UInt32.max << (32 - prefix)), prefix)
    }
    let masks: [UInt32] = [0, 0xffffffff, 0xfffffffe, 0xff00ff00, 0x00ffffff]
    for mask in masks {
      XCTAssertNil(NearbyDiagnosticTarget.prefixLength(mask))
    }
  }

  func testNearbyDiagnosticTypedBounds() {
    let invalid: [(String, Any)] = [
      ("port", 0), ("port", 65536), ("port", true), ("port", 6809.0), ("port", "6809"),
      ("interfaceIndex", 0), ("interfaceIndex", 7.0), ("generation", -1),
      ("controller", true), ("request", Int64.max), ("prefixLength", 0), ("prefixLength", 31),
      ("run", "production"), ("run", "g2-users-20261024-pin-a\n"), ("attempt", "not-a-uuid")
    ]
    for (key, value) in invalid {
      var args = diagnosticArguments()
      args[key] = value
      XCTAssertNil(NearbyDiagnosticTarget.parse(args), key)
    }
    var maximum = diagnosticArguments()
    maximum["port"] = 65535
    maximum["interfaceIndex"] = Int32.max
    XCTAssertNotNil(NearbyDiagnosticTarget.parse(maximum))
  }

  func testNearbyDiagnosticExactFields() {
    let valid = diagnosticArguments()
    for key in valid.keys {
      var args = valid
      args.removeValue(forKey: key)
      XCTAssertNil(NearbyDiagnosticTarget.parse(args), key)
    }
    var extra = valid
    extra["payload"] = "must-not-be-accepted"
    XCTAssertNil(NearbyDiagnosticTarget.parse(extra))
    XCTAssertNil(NearbyDiagnosticTarget.parse(["arbitrary"]))
    XCTAssertNil(NearbyDiagnosticTarget.parse(nil))
  }

  func testNearbyDiagnosticIPv4Syntax() {
    for address in ["", "1.2.3", "1.2.3.4.5", "192.168.010.40", "192.168.10.256",
      "192.168.10.-1", "192.168.10.40\n", " 192.168.10.40", "192.168.10.40:6809"] {
      XCTAssertNil(NearbyDiagnosticTarget.ipv4(address), address)
    }
    XCTAssertEqual(NearbyDiagnosticTarget.ipv4("192.168.10.40"), 0xc0a80a28)
    XCTAssertFalse(NearbyDiagnosticTarget.isPrivate(0x08080808))
    XCTAssertFalse(NearbyDiagnosticTarget.isPrivate(0xac200001))
    XCTAssertTrue(NearbyDiagnosticTarget.isPrivate(0xac1ffffe))
  }
  #endif

  func testInstallationSecurityNamespaceAcceptsBoundedCompanyUserSlots() throws {
    for slot in 1...2 {
      let name = "production.company-user-\(slot)"
      XCTAssertEqual(try InstallationSecurityNamespace(name).rawValue, name)
    }
  }

  func testInstallationSecurityNamespacePreservesExistingNames() throws {
    let names = [
      "production",
      "production.company-custody",
      "synthetic.0",
      "synthetic.a-z_9",
      "synthetic.production",
      "synthetic.production.company-custody",
      "synthetic.production.company-user-1",
      "synthetic.production.company-user-2",
      "synthetic.production.company-user-3",
    ]

    for name in names {
      XCTAssertEqual(try InstallationSecurityNamespace(name).rawValue, name)
    }
  }

  func testInstallationSecurityNamespaceEnforcesMaximumByteLength() throws {
    let maximumLengthName = "synthetic." + String(repeating: "a", count: 54)

    XCTAssertEqual(
      try InstallationSecurityNamespace(maximumLengthName).rawValue, maximumLengthName)
    XCTAssertThrowsError(try InstallationSecurityNamespace(maximumLengthName + "a")) { error in
      guard let storeError = error as? StoreError,
        case .invalidArgument = storeError else {
        XCTFail("Expected an invalid-argument failure, received \(error)")
        return
      }
      XCTAssertEqual(storeError.code, "installation_invalid_argument")
    }
  }

  func testInstallationSecurityNamespaceRejectsProductionLookalikes() {
    let names = [
      "production.company-user-0",
      "production.company-user-3",
      "production.company-user-01",
      "production.company-user-02",
      "production.company-user--1",
      "production.company-user-+1",
      "production.company-user-",
      "production.company-user-999999999999999999999999999999",
      "xproduction.company-user-1",
      "production.company-user-1.extra",
      "production.company-user-2.extra",
      "production.company-User-1",
      "production.company-custody.extra",
    ]

    for name in names {
      XCTAssertThrowsError(try InstallationSecurityNamespace(name), name) { error in
        guard let storeError = error as? StoreError,
          case .invalidArgument = storeError else {
          XCTFail("Expected an invalid-argument failure for \(name), received \(error)")
          return
        }
        XCTAssertEqual(storeError.code, "installation_invalid_argument", name)
      }
    }
  }

  func testInstallationSecurityNamespaceRejectsInvalidSyntax() {
    let names = [
      "",
      "synthetic.",
      "synthetic._a",
      "synthetic.-a",
      "synthetic..a",
      "synthetic.a+b",
      "synthetic.caf\u{00e9}",
      "synthetic.a/b",
    ]

    for name in names {
      XCTAssertThrowsError(try InstallationSecurityNamespace(name), name) { error in
        guard let storeError = error as? StoreError,
          case .invalidArgument = storeError else {
          XCTFail("Expected an invalid-argument failure for \(name), received \(error)")
          return
        }
        XCTAssertEqual(storeError.code, "installation_invalid_argument", name)
      }
    }
  }

  func testRecoveryPublisherWritesExactBytes() throws {
    try withTemporaryDestination { destination in
      let bytes = Data([0x00, 0x7f, 0x80, 0xff, 0x0a])
      let written = try RecoveryFilePublisher.writeExclusive(path: destination.path, bytes: bytes)

      XCTAssertEqual(written, 5)
      XCTAssertEqual(try Data(contentsOf: destination), bytes)
      var info = stat()
      XCTAssertEqual(lstat(destination.path, &info), 0)
      XCTAssertEqual(info.st_mode & mode_t(0o777), mode_t(0o600))
      XCTAssertEqual(info.st_uid, geteuid())
      XCTAssertEqual(info.st_nlink, 1)
    }
  }

  func testRecoveryPublisherFlushesParentBeforeFile() throws {
    try withTemporaryDestination { destination in
      let bytes = Data([10, 20, 30])
      var flushes: [String] = []
      let written = try RecoveryFilePublisher.writeExclusive(
        path: destination.path,
        bytes: bytes,
        synchronizeDirectory: { descriptor in
          var actual = stat()
          var expected = stat()
          XCTAssertEqual(fstat(descriptor, &actual), 0)
          XCTAssertEqual(stat(destination.deletingLastPathComponent().path, &expected), 0)
          XCTAssertEqual(actual.st_mode & mode_t(S_IFMT), mode_t(S_IFDIR))
          XCTAssertEqual(actual.st_dev, expected.st_dev)
          XCTAssertEqual(actual.st_ino, expected.st_ino)
          XCTAssertEqual(try? Data(contentsOf: destination), bytes)
          flushes.append("directory")
          return 0
        },
        fullSynchronizeFile: { descriptor in
          var actual = stat()
          var expected = stat()
          XCTAssertEqual(fstat(descriptor, &actual), 0)
          XCTAssertEqual(lstat(destination.path, &expected), 0)
          XCTAssertEqual(actual.st_mode & mode_t(S_IFMT), mode_t(S_IFREG))
          XCTAssertEqual(actual.st_dev, expected.st_dev)
          XCTAssertEqual(actual.st_ino, expected.st_ino)
          XCTAssertEqual(try? Data(contentsOf: destination), bytes)
          flushes.append("file")
          return 0
        })

      XCTAssertEqual(written, 3)
      XCTAssertEqual(flushes, ["directory", "file"])
      XCTAssertEqual(try Data(contentsOf: destination), bytes)
    }
  }

  func testRecoveryPublisherUsesParentForCombiningMarkFilename() throws {
    try withTemporaryDestination { destination in
      let parent = destination.deletingLastPathComponent()
      let unicodeDestination = parent.appendingPathComponent("\u{0301}recovery.json")
      let written = try RecoveryFilePublisher.writeExclusive(
        path: unicodeDestination.path,
        bytes: Data([160, 170, 180]),
        synchronizeDirectory: { descriptor in
          var actual = stat()
          var expected = stat()
          XCTAssertEqual(fstat(descriptor, &actual), 0)
          XCTAssertEqual(stat(parent.path, &expected), 0)
          XCTAssertEqual(actual.st_dev, expected.st_dev)
          XCTAssertEqual(actual.st_ino, expected.st_ino)
          return 0
        },
        fullSynchronizeFile: { _ in 0 })

      XCTAssertEqual(written, 3)
      XCTAssertEqual(try Data(contentsOf: unicodeDestination), Data([160, 170, 180]))
    }
  }

  func testRecoveryPublisherRejectsDirectoryFlushFailure() throws {
    try withTemporaryDestination { destination in
      let bytes = Data([40, 50, 60])
      var fileFlushCalled = false
      assertOperatingSystemFailure(EIO) {
        try RecoveryFilePublisher.writeExclusive(
          path: destination.path,
          bytes: bytes,
          synchronizeDirectory: { _ in
            errno = EIO
            return -1
          },
          fullSynchronizeFile: { _ in
            fileFlushCalled = true
            errno = ENOSPC
            return -1
          })
      }

      XCTAssertFalse(fileFlushCalled)
      XCTAssertEqual(try Data(contentsOf: destination), bytes)
    }
  }

  func testRecoveryPublisherRejectsFullFileFlushFailure() throws {
    try withTemporaryDestination { destination in
      let bytes = Data([70, 80, 90])
      var flushes: [String] = []
      assertOperatingSystemFailure(ENOSPC) {
        try RecoveryFilePublisher.writeExclusive(
          path: destination.path,
          bytes: bytes,
          synchronizeDirectory: { _ in
            flushes.append("directory")
            return 0
          },
          fullSynchronizeFile: { _ in
            flushes.append("file")
            errno = ENOSPC
            return -1
          })
      }

      XCTAssertEqual(flushes, ["directory", "file"])
      XCTAssertEqual(try Data(contentsOf: destination), bytes)
    }
  }

  func testRecoveryPublisherPreservesExistingFile() throws {
    try withTemporaryDestination { destination in
      let original = Data([100, 110, 120])
      try original.write(to: destination)
      var flushCalled = false
      assertOperatingSystemFailure(EEXIST) {
        try RecoveryFilePublisher.writeExclusive(
          path: destination.path,
          bytes: Data([130, 140, 150]),
          synchronizeDirectory: { _ in
            flushCalled = true
            return 0
          },
          fullSynchronizeFile: { _ in
            flushCalled = true
            return 0
          })
      }

      XCTAssertFalse(flushCalled)
      XCTAssertEqual(try Data(contentsOf: destination), original)
    }
  }

  private func withTemporaryDestination(_ body: (URL) throws -> Void) throws {
    let directory = FileManager.default.temporaryDirectory
      .appendingPathComponent("recovery-publisher-" + UUID().uuidString, isDirectory: true)
    try FileManager.default.createDirectory(
      at: directory, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
    defer { try? FileManager.default.removeItem(at: directory) }
    try body(directory.appendingPathComponent("recovery.json"))
  }

  private func assertOperatingSystemFailure(
    _ expected: Int32,
    file: StaticString = #filePath,
    line: UInt = #line,
    operation: () throws -> Int
  ) {
    XCTAssertThrowsError(try operation(), file: file, line: line) { error in
      guard let storeError = error as? StoreError,
        case .operatingSystem(let number) = storeError else {
        XCTFail("Expected an operating-system failure, received \(error)", file: file, line: line)
        return
      }
      XCTAssertEqual(number, expected, file: file, line: line)
    }
  }
}
