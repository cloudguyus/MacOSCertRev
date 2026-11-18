import CryptoKit
import Darwin
import Foundation
import Security
import SwiftASN1

/// Imports a PKCS#12 bundle without putting the key or the password in the keychain.
enum PKCS12Reader {
    private static let maxMACIterations = 5_000_000

    /// RC2 and 3DES algorithms used by legacy PKCS#12. AES-256 PBES2 is not in this list.
    private static let legacyOIDs: [ASN1ObjectIdentifier] = [
        ASN1ObjectIdentifier(arrayLiteral: 1, 2, 840, 113549, 1, 12, 1, 3), // pbeWithSHAAnd3-KeyTripleDES-CBC
        ASN1ObjectIdentifier(arrayLiteral: 1, 2, 840, 113549, 1, 12, 1, 4), // pbeWithSHAAnd2-KeyTripleDES-CBC
        ASN1ObjectIdentifier(arrayLiteral: 1, 2, 840, 113549, 1, 12, 1, 5), // pbeWithSHAAnd128BitRC2-CBC
        ASN1ObjectIdentifier(arrayLiteral: 1, 2, 840, 113549, 1, 12, 1, 6), // pbeWithSHAAnd40BitRC2-CBC
        ASN1ObjectIdentifier(arrayLiteral: 1, 2, 840, 113549, 3, 2), // rc2-cbc
        ASN1ObjectIdentifier(arrayLiteral: 1, 3, 14, 3, 2, 7), // des-ede3-cbc
    ]

    static func looksLikeBundle(_ data: Data) -> Bool {
        guard let root = try? DER.parse([UInt8](data)),
              root.identifier == .sequence,
              case .constructed(let nodes) = root.content
        else { return false }
        let parts = Array(nodes)
        guard let version = parts.first, let value = integerValue(version) else { return false }
        return value == 3 && parts.count >= 2
    }

    static func usesLegacyEncryption(_ data: Data) -> Bool {
        guard let safe = authenticatedSafeNode(data) else { return false }
        return containsLegacyOID(safe)
    }

    static func importBundle(_ data: Data, password: String) throws -> [LoadedCertificate] {
        var passwordBytes = pkcs12PasswordBytes(password)
        defer { wipe(&passwordBytes) }

        let mac = macStatus(data, password: passwordBytes)
        if mac == .didNotMatch {
            throw CertificateLoadError.pkcs12WrongPassword
        }

        let verified = mac == .matched
        let (status, items) = securityImport(data, password: password)
        guard status == errSecSuccess, let items else {
            if isAuthenticationFailure(status), !verified {
                throw CertificateLoadError.pkcs12WrongPassword
            }
            if usesLegacyEncryption(data) {
                throw CertificateLoadError.pkcs12LegacyEncryption
            }
            throw CertificateLoadError.pkcs12Corrupt
        }
        return try certificates(from: items)
    }

    /// `SecPKCS12Import` keeps the key in memory when `kSecImportToMemoryOnly` is set.
    /// The password exists only for this call. Nothing is added to the keychain.
    private static func securityImport(_ data: Data, password: String) -> (OSStatus, CFArray?) {
        let options = [
            kSecImportExportPassphrase as String: password,
            kSecImportToMemoryOnly as String: kCFBooleanTrue as Any,
        ] as CFDictionary
        var items: CFArray?
        let status = SecPKCS12Import(data as CFData, options, &items)
        return (status, items)
    }

    private static func certificates(from items: CFArray) throws -> [LoadedCertificate] {
        let array = items as NSArray
        var ders: [Data] = []
        var seen = Set<Data>()
        var keys: [Data: PrivateKeySummary] = [:]

        func appendCertificate(_ certificate: SecCertificate, key: PrivateKeySummary?) {
            let der = SecCertificateCopyData(certificate) as Data
            if seen.insert(der).inserted {
                ders.append(der)
            }
            if let key {
                keys[der] = key
            }
        }

        for element in array {
            guard let item = element as? NSDictionary else { continue }
            if let identity = secIdentity(item.object(forKey: kSecImportItemIdentity)) {
                let summary = privateKeySummary(identity)
                var certificate: SecCertificate?
                if SecIdentityCopyCertificate(identity, &certificate) == errSecSuccess, let certificate {
                    appendCertificate(certificate, key: summary)
                }
            }
            if let chain = item.object(forKey: kSecImportItemCertChain) as? NSArray {
                for element in chain {
                    guard let certificate = secCertificate(element) else { continue }
                    appendCertificate(certificate, key: nil)
                }
            }
        }

        guard !ders.isEmpty else { throw CertificateLoadError.pkcs12Corrupt }
        let ordered: [CertificateChainOrder.Item]
        do {
            ordered = try CertificateChainOrder.order(ders)
        } catch {
            throw CertificateLoadError.pkcs12Corrupt
        }
        return ordered.map { item in
            LoadedCertificate(der: item.der, unchained: item.unchained, privateKey: keys[item.der])
        }
    }

    /// `as? SecIdentity` is a compile error: Swift treats a conditional downcast to a
    /// CoreFoundation type as one that always succeeds. Compare type IDs, then force-cast.
    private static func secIdentity(_ value: Any?) -> SecIdentity? {
        guard let value else { return nil }
        let object = value as AnyObject
        guard CFGetTypeID(object) == SecIdentityGetTypeID() else { return nil }
        return object as! SecIdentity
    }

    private static func secCertificate(_ value: Any?) -> SecCertificate? {
        guard let value else { return nil }
        let object = value as AnyObject
        guard CFGetTypeID(object) == SecCertificateGetTypeID() else { return nil }
        return object as! SecCertificate
    }

    /// Reads type and size. `SecKeyCopyExternalRepresentation` is intentionally not called.
    private static func privateKeySummary(_ identity: SecIdentity) -> PrivateKeySummary? {
        var key: SecKey?
        guard SecIdentityCopyPrivateKey(identity, &key) == errSecSuccess, let key else { return nil }
        let attributes = SecKeyCopyAttributes(key) as? [CFString: Any]
        let type = attributes?[kSecAttrKeyType] as? String
        let algorithm: String
        if type == (kSecAttrKeyTypeRSA as String) {
            algorithm = "RSA"
        } else if type == (kSecAttrKeyTypeECSECPrimeRandom as String) {
            algorithm = "EC"
        } else {
            algorithm = "Private key"
        }
        let bits = keySizeBits(attributes) ?? (algorithm == "RSA" ? SecKeyGetBlockSize(key) * 8 : 0)
        return PrivateKeySummary(algorithm: algorithm, sizeBits: bits)
    }

    private static func keySizeBits(_ attributes: [CFString: Any]?) -> Int? {
        guard let value = attributes?[kSecAttrKeySizeInBits] else { return nil }
        if let number = value as? NSNumber { return number.intValue }
        if let number = value as? Int { return number }
        return nil
    }

    private static func isAuthenticationFailure(_ status: OSStatus) -> Bool {
        if status == errSecAuthFailed { return true }
        // errSecPkcs12VerifyFailure. The MAC check covers files that have a MAC;
        // this status is the fallback when the file has none.
        return status == OSStatus(-25264)
    }

    // MARK: - MAC

    private enum MACStatus {
        case absent
        case matched
        case didNotMatch
        case unchecked
    }

    private enum MACHash {
        case sha1
        case sha256
        case sha384
        case sha512

        var length: Int {
            switch self {
            case .sha1: return 20
            case .sha256: return 32
            case .sha384: return 48
            case .sha512: return 64
            }
        }

        init?(oid: ASN1ObjectIdentifier) {
            if oid == ASN1ObjectIdentifier(arrayLiteral: 1, 3, 14, 3, 2, 26) {
                self = .sha1
            } else if oid == ASN1ObjectIdentifier(arrayLiteral: 2, 16, 840, 1, 101, 3, 4, 2, 1) {
                self = .sha256
            } else if oid == ASN1ObjectIdentifier(arrayLiteral: 2, 16, 840, 1, 101, 3, 4, 2, 2) {
                self = .sha384
            } else if oid == ASN1ObjectIdentifier(arrayLiteral: 2, 16, 840, 1, 101, 3, 4, 2, 3) {
                self = .sha512
            } else {
                return nil
            }
        }
    }

    /// Checks the PKCS#12 MAC (RFC 7292) so a wrong password is distinct from a
    /// legacy cipher the system importer cannot decrypt.
    private static func macStatus(_ data: Data, password: [UInt8]) -> MACStatus {
        guard let root = try? DER.parse([UInt8](data)),
              case .constructed(let nodes) = root.content
        else { return .unchecked }
        let parts = Array(nodes)
        guard parts.count >= 2, let macInput = authenticatedSafeBytes(parts[1]) else { return .unchecked }
        guard parts.count >= 3, let mac = parseMAC(parts[2]) else { return .absent }
        guard (1...maxMACIterations).contains(mac.iterations), let hash = MACHash(oid: mac.algorithm) else {
            return .unchecked
        }

        var key = deriveKey(
            password: password,
            salt: mac.salt,
            iterations: mac.iterations,
            length: hash.length,
            hash: hash
        )
        defer { wipe(&key) }
        let computed = hmac(hash, key: key, data: macInput)
        return constantTimeEqual(computed, mac.digest) ? .matched : .didNotMatch
    }

    private struct MACData {
        var algorithm: ASN1ObjectIdentifier
        var digest: [UInt8]
        var salt: [UInt8]
        var iterations: Int
    }

    private static func parseMAC(_ node: ASN1Node) -> MACData? {
        guard case .constructed(let nodes) = node.content else { return nil }
        let parts = Array(nodes)
        guard let digestInfo = parts.first, case .constructed(let digestNodes) = digestInfo.content else { return nil }
        let digestParts = Array(digestNodes)
        guard digestParts.count >= 2,
              case .constructed(let algorithmNodes) = digestParts[0].content,
              let oidNode = Array(algorithmNodes).first,
              let algorithm = try? ASN1ObjectIdentifier(derEncoded: oidNode),
              let digest = octetBytes(digestParts[1]),
              parts.count >= 2,
              let salt = octetBytes(parts[1])
        else { return nil }
        let iterations = parts.count >= 3 ? (integerValue(parts[2]) ?? 1) : 1
        return MACData(algorithm: algorithm, digest: digest, salt: salt, iterations: iterations)
    }

    /// PKCS#12 passwords are UTF-16BE with a trailing NUL. The caller wipes the result.
    private static func pkcs12PasswordBytes(_ password: String) -> [UInt8] {
        var bytes: [UInt8] = []
        bytes.reserveCapacity(password.utf16.count * 2 + 2)
        for unit in password.utf16 {
            bytes.append(UInt8(unit >> 8))
            bytes.append(UInt8(truncatingIfNeeded: unit))
        }
        bytes.append(0)
        bytes.append(0)
        return bytes
    }

    /// RFC 7292 Appendix B, ID 3 (MAC key).
    private static func deriveKey(
        password: [UInt8],
        salt: [UInt8],
        iterations: Int,
        length: Int,
        hash: MACHash
    ) -> [UInt8] {
        let u = hash.length
        let v = 64
        let d = [UInt8](repeating: 3, count: v)
        let s = expand(salt, block: v)
        var expandedPassword = expand(password, block: v)
        var i = s + expandedPassword
        let blocks = max(1, (length + u - 1) / u)
        var result: [UInt8] = []
        result.reserveCapacity(blocks * u)
        defer {
            wipe(&expandedPassword)
            wipe(&i)
        }

        for _ in 0..<blocks {
            var diversified = Self.hash(hash, d + i)
            if iterations > 1 {
                for _ in 1..<iterations {
                    let next = Self.hash(hash, diversified)
                    wipe(&diversified)
                    diversified = next
                }
            }
            result.append(contentsOf: diversified)

            var b = [UInt8]()
            b.reserveCapacity(v)
            while b.count < v {
                b.append(contentsOf: diversified)
            }
            if b.count > v {
                b.removeLast(b.count - v)
            }
            wipe(&diversified)
            add(b, to: &i, block: v)
            wipe(&b)
        }
        if result.count > length {
            result.removeLast(result.count - length)
        }
        return result
    }

    private static func expand(_ bytes: [UInt8], block: Int) -> [UInt8] {
        guard !bytes.isEmpty else { return [] }
        let count = ((bytes.count + block - 1) / block) * block
        var out: [UInt8] = []
        out.reserveCapacity(count)
        while out.count < count {
            out.append(contentsOf: bytes)
        }
        if out.count > count {
            out.removeLast(out.count - count)
        }
        return out
    }

    private static func add(_ block: [UInt8], to value: inout [UInt8], block width: Int) {
        var offset = 0
        while offset < value.count {
            var carry = 1
            var index = width - 1
            while index >= 0 {
                let sum = Int(value[offset + index]) + Int(block[index]) + carry
                value[offset + index] = UInt8(sum & 0xFF)
                carry = sum >> 8
                index -= 1
            }
            offset += width
        }
    }

    private static func hash(_ hash: MACHash, _ data: [UInt8]) -> [UInt8] {
        let input = Data(data)
        switch hash {
        case .sha1:
            return Array(Insecure.SHA1.hash(data: input))
        case .sha256:
            return Array(SHA256.hash(data: input))
        case .sha384:
            return Array(SHA384.hash(data: input))
        case .sha512:
            return Array(SHA512.hash(data: input))
        }
    }

    private static func hmac(_ hash: MACHash, key: [UInt8], data: [UInt8]) -> [UInt8] {
        let symmetric = SymmetricKey(data: Data(key))
        let message = Data(data)
        switch hash {
        case .sha1:
            return Array(HMAC<Insecure.SHA1>.authenticationCode(for: message, using: symmetric))
        case .sha256:
            return Array(HMAC<SHA256>.authenticationCode(for: message, using: symmetric))
        case .sha384:
            return Array(HMAC<SHA384>.authenticationCode(for: message, using: symmetric))
        case .sha512:
            return Array(HMAC<SHA512>.authenticationCode(for: message, using: symmetric))
        }
    }

    private static func constantTimeEqual(_ lhs: [UInt8], _ rhs: [UInt8]) -> Bool {
        guard lhs.count == rhs.count else { return false }
        var difference: UInt8 = 0
        for (left, right) in zip(lhs, rhs) {
            difference |= left ^ right
        }
        return difference == 0
    }

    // MARK: - ASN.1

    private static func authenticatedSafeNode(_ data: Data) -> ASN1Node? {
        guard let root = try? DER.parse([UInt8](data)),
              case .constructed(let nodes) = root.content
        else { return nil }
        let parts = Array(nodes)
        guard parts.count >= 2, let bytes = authenticatedSafeBytes(parts[1]) else { return nil }
        return try? DER.parse(bytes)
    }

    private static func authenticatedSafeBytes(_ contentInfo: ASN1Node) -> [UInt8]? {
        guard case .constructed(let nodes) = contentInfo.content else { return nil }
        let parts = Array(nodes)
        guard parts.count >= 2, case .constructed(let explicit) = parts[1].content else { return nil }
        guard let octet = Array(explicit).first else { return nil }
        return octetBytes(octet)
    }

    private static func containsLegacyOID(_ node: ASN1Node) -> Bool {
        if node.identifier == .objectIdentifier,
           let oid = try? ASN1ObjectIdentifier(derEncoded: node),
           legacyOIDs.contains(oid) {
            return true
        }
        guard case .constructed(let children) = node.content, node.identifier != .octetString else {
            return false
        }
        for child in children where containsLegacyOID(child) {
            return true
        }
        return false
    }

    private static func octetBytes(_ node: ASN1Node) -> [UInt8]? {
        guard node.identifier == .octetString, case .primitive(let bytes) = node.content else { return nil }
        return Array(bytes)
    }

    private static func integerValue(_ node: ASN1Node) -> Int? {
        guard node.identifier == .integer, case .primitive(let bytes) = node.content else { return nil }
        guard !bytes.isEmpty, bytes.count <= 8, let first = bytes.first, first & 0x80 == 0 else { return nil }
        var value = 0
        for byte in bytes {
            value = (value << 8) | Int(byte)
        }
        return value
    }

    /// `memset_s` is used so the compiler cannot drop the clear of password and key bytes.
    private static func wipe(_ bytes: inout [UInt8]) {
        guard !bytes.isEmpty else { return }
        bytes.withUnsafeMutableBytes { buffer in
            guard let base = buffer.baseAddress else { return }
            _ = memset_s(base, buffer.count, Int32(0), buffer.count)
        }
    }
}
