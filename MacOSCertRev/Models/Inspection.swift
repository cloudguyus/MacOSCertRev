import Foundation

struct FieldRow: Identifiable, Hashable, Sendable {
    let id: String
    let title: String
    let value: String
    let subtitle: String?
}

struct FieldSection: Identifiable, Hashable, Sendable {
    let id: String
    let title: String
    let rows: [FieldRow]
}

struct CertificateSummary: Hashable, Sendable {
    let commonName: String
    let subject: String
    let issuer: String
    let serialHex: String
    let notBefore: Date
    let notAfter: Date
}

/// Type and size of a private key that arrived with a certificate.
///
/// This is the only information CertRev keeps. The key bytes and the PKCS#12
/// password are never stored here.
struct PrivateKeySummary: Hashable, Sendable, CustomStringConvertible, CustomDebugStringConvertible {
    let algorithm: String
    let sizeBits: Int

    var description: String {
        guard sizeBits > 0 else { return algorithm }
        return "\(algorithm) \(sizeBits)-bit"
    }

    var debugDescription: String { description }
}

struct ParsedCertificate: Identifiable, Hashable, Sendable {
    let id: Int
    let der: Data
    let summary: CertificateSummary
    let sections: [FieldSection]
    /// Set when the opened bundle included a private key for this certificate.
    let privateKey: PrivateKeySummary?
    /// Set when this certificate does not link to another certificate in the same bundle.
    let unchained: Bool
}

/// One certificate extracted from a file, plus bundle-only facts about it.
struct LoadedCertificate: Equatable, Sendable, CustomStringConvertible, CustomDebugStringConvertible {
    var der: Data
    var unchained: Bool
    var privateKey: PrivateKeySummary?

    init(der: Data, unchained: Bool = false, privateKey: PrivateKeySummary? = nil) {
        self.der = der
        self.unchained = unchained
        self.privateKey = privateKey
    }

    var description: String {
        "LoadedCertificate(unchained: \(unchained), privateKey: \(privateKey?.description ?? "none"))"
    }

    var debugDescription: String { description }
}

struct TrustReport: Equatable, Sendable {
    let succeeded: Bool
    let message: String
    let chain: [String]
}

struct TrustEvaluationOptions: Sendable {
    var networkFetchAllowed: Bool
    /// When set, evaluation trusts only these certificates. `nil` uses the system trust store.
    var anchorDERs: [Data]?
}

enum CertificateLoadError: Error, Equatable, LocalizedError {
    case empty
    case privateKey
    case pkcs12PasswordRequired
    case pkcs12WrongPassword
    case pkcs12LegacyEncryption
    case pkcs12BlankPasswordEncoding
    case pkcs12Corrupt
    case pkcs7NotACertificateBundle
    case pkcs7Corrupt
    case crl
    case notACertificate(fileName: String)

    var errorDescription: String? {
        switch self {
        case .empty:
            return "The file is empty."
        case .privateKey:
            return "This file contains a private key. CertRev only opens certificates."
        case .pkcs12PasswordRequired:
            return "This PKCS#12 file needs a password."
        case .pkcs12WrongPassword:
            return "The password is incorrect."
        case .pkcs12LegacyEncryption:
            return "This PKCS#12 file uses legacy RC2 or 3DES encryption, which this version of macOS cannot open. Export it again with AES-256."
        case .pkcs12BlankPasswordEncoding:
            return "This PKCS#12 file uses a blank-password encoding that this version of macOS cannot import. Export it again and set a password."
        case .pkcs12Corrupt:
            return "This PKCS#12 file is corrupt or is not a PKCS#12 bundle."
        case .pkcs7NotACertificateBundle:
            return "This PKCS#7 file is signed or enveloped data, not a certificate bundle."
        case .pkcs7Corrupt:
            return "This PKCS#7 file is corrupt or is not a PKCS#7 bundle."
        case .crl:
            return "Certificate revocation lists are not supported yet."
        case .notACertificate(let fileName):
            return "\(fileName) is not a certificate."
        }
    }
}
