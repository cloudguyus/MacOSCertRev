import Foundation
import SwiftASN1

/// Reads certificates out of a certs-only PKCS#7 SignedData value.
enum PKCS7Reader {
    private static let pkcs7Data: ASN1ObjectIdentifier = [1, 2, 840, 113549, 1, 7, 1]
    private static let signedData: ASN1ObjectIdentifier = [1, 2, 840, 113549, 1, 7, 2]
    private static let envelopedData: ASN1ObjectIdentifier = [1, 2, 840, 113549, 1, 7, 3]
    private static let signedAndEnvelopedData: ASN1ObjectIdentifier = [1, 2, 840, 113549, 1, 7, 4]
    private static let digestedData: ASN1ObjectIdentifier = [1, 2, 840, 113549, 1, 7, 5]
    private static let encryptedData: ASN1ObjectIdentifier = [1, 2, 840, 113549, 1, 7, 6]

    static func certificateDERs(from der: Data) throws -> [Data] {
        let root: ASN1Node
        do {
            root = try DER.parse([UInt8](der))
        } catch {
            throw CertificateLoadError.pkcs7Corrupt
        }
        guard case .constructed(let top) = root.content else {
            throw CertificateLoadError.pkcs7Corrupt
        }
        let parts = Array(top)
        guard parts.count >= 2, let type = try? ASN1ObjectIdentifier(derEncoded: parts[0]) else {
            throw CertificateLoadError.pkcs7Corrupt
        }
        guard let body = explicitChild(parts[1]) else {
            throw CertificateLoadError.pkcs7Corrupt
        }

        if type == signedData {
            return try signedDataCertificates(body)
        }
        if type == envelopedData || type == signedAndEnvelopedData || type == digestedData || type == encryptedData || type == pkcs7Data {
            throw CertificateLoadError.pkcs7NotACertificateBundle
        }
        throw CertificateLoadError.pkcs7Corrupt
    }

    private static func signedDataCertificates(_ node: ASN1Node) throws -> [Data] {
        guard case .constructed(let nodes) = node.content else {
            throw CertificateLoadError.pkcs7Corrupt
        }
        let parts = Array(nodes)
        guard parts.count >= 4,
              parts[0].identifier == .integer,
              parts[1].identifier == .set,
              parts[2].identifier == .sequence
        else {
            throw CertificateLoadError.pkcs7Corrupt
        }
        if encapsulatedContentIsPresent(parts[2]) {
            throw CertificateLoadError.pkcs7NotACertificateBundle
        }

        var index = 3
        var certificates: [Data] = []
        if index < parts.count, isContextSpecific(parts[index], tag: 0) {
            certificates = sequenceChildren(parts[index])
            index += 1
        }
        if index < parts.count, isContextSpecific(parts[index], tag: 1) {
            index += 1
        }
        guard index < parts.count, parts[index].identifier == .set else {
            throw CertificateLoadError.pkcs7Corrupt
        }
        if childCount(parts[index]) > 0 {
            throw CertificateLoadError.pkcs7NotACertificateBundle
        }
        guard !certificates.isEmpty else {
            throw CertificateLoadError.pkcs7NotACertificateBundle
        }
        return certificates
    }

    /// `eContent` is present when the encapsulated content info has a non-empty `[0] EXPLICIT` value.
    private static func encapsulatedContentIsPresent(_ node: ASN1Node) -> Bool {
        guard case .constructed(let nodes) = node.content else { return false }
        let parts = Array(nodes)
        guard parts.count >= 2, let content = explicitChild(parts[1]) else { return false }
        if case .primitive(let bytes) = content.content, bytes.isEmpty { return false }
        return true
    }

    private static func explicitChild(_ node: ASN1Node) -> ASN1Node? {
        guard case .constructed(let nodes) = node.content else { return nil }
        var iterator = nodes.makeIterator()
        return iterator.next()
    }

    private static func sequenceChildren(_ node: ASN1Node) -> [Data] {
        guard case .constructed(let nodes) = node.content else { return [] }
        return nodes.compactMap { child in
            guard child.identifier == .sequence else { return nil }
            return Data(child.encodedBytes)
        }
    }

    private static func childCount(_ node: ASN1Node) -> Int {
        guard case .constructed(let nodes) = node.content else { return 0 }
        return Array(nodes).count
    }

    private static func isContextSpecific(_ node: ASN1Node, tag: UInt) -> Bool {
        node.identifier.tagClass == .contextSpecific && node.identifier.tagNumber == tag
    }
}
