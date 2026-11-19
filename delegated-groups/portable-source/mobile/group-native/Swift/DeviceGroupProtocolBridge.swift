import Foundation
import SecureGroupNative

/// Pure native adapter. The SQLCipher host must supply committed history and
/// highest trusted rosters, then commit preview results atomically. No network
/// dispatcher may expose this as a generic signing endpoint.
enum DeviceGroupProtocolBridge {
    static let maximumRequestBytes = 72 * 1_024 * 1_024
    static let maximumResultBytes = 40 * 1_024 * 1_024

    static func execute(_ request: [String: Any], signer: LocalDeviceIdentity? = nil,
                        groupKey: Data? = nil) throws -> [String: Any] {
        guard let operation = request["operation"] as? String, operation != "ratify",
              groupKey == nil || groupKey?.count == 32 else { throw Failure.invalidArguments }
        let signing = ["create_operation", "attest_history", "attest_invitation"].contains(operation)
        guard signing == (signer != nil) else { throw Failure.invalidArguments }
        let bytes = try JSONSerialization.data(withJSONObject: request, options: [.sortedKeys])
        guard !bytes.isEmpty, bytes.count <= maximumRequestBytes else { throw Failure.invalidArguments }
        if let signer {
            return try signer.withGroupSigningSeed { seed in
                try invoke(bytes, seed: seed, key: groupKey)
            }
        }
        return try invoke(bytes, seed: nil, key: groupKey)
    }

    private static func invoke(_ request: Data, seed: Data?, key: Data?) throws -> [String: Any] {
        var capacity = 256 * 1_024
        for _ in 0..<3 {
            var output = Data(count: capacity)
            defer { output.resetBytes(in: 0..<output.count) }
            var count = UInt32(capacity)
            let code: Int32 = request.withUnsafeBytes { requestBuffer in
                output.withUnsafeMutableBytes { outputBuffer in
                    func call(_ seedPointer: UnsafePointer<UInt8>?, _ keyPointer: UnsafePointer<UInt8>?) -> Int32 {
                        sl_desktop_group_protocol(requestBuffer.bindMemory(to: UInt8.self).baseAddress,
                            UInt32(request.count), seedPointer, seed == nil ? 0 : 32,
                            keyPointer, key == nil ? 0 : 32,
                            outputBuffer.bindMemory(to: UInt8.self).baseAddress, &count)
                    }
                    func withKey(_ seedPointer: UnsafePointer<UInt8>?) -> Int32 {
                        if let key {
                            return key.withUnsafeBytes { call(seedPointer, $0.bindMemory(to: UInt8.self).baseAddress) }
                        }
                        return call(seedPointer, nil)
                    }
                    if let seed {
                        return seed.withUnsafeBytes { withKey($0.bindMemory(to: UInt8.self).baseAddress) }
                    }
                    return withKey(nil)
                }
            }
            if code == 0 {
                guard count > 0, Int(count) <= capacity,
                      let value = try JSONSerialization.jsonObject(with: output.prefix(Int(count))) as? [String: Any]
                else { throw Failure.invalidResult }
                return value
            }
            guard code == -2 else { throw Failure.native(code) }
            guard Int(count) > capacity, Int(count) <= maximumResultBytes else { throw Failure.invalidResult }
            capacity = Int(count)
        }
        throw Failure.invalidResult
    }

    enum Failure: Error, LocalizedError {
        case invalidArguments, invalidResult, native(Int32)
        var errorDescription: String? {
            switch self {
            case .invalidArguments: "Invalid group operation arguments"
            case .invalidResult: "Invalid native group result"
            case .native(let code): "Group operation failed (\(code))"
            }
        }
    }
}
