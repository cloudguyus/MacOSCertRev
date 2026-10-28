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

struct ParsedCertificate: Identifiable, Hashable, Sendable {
    let id: Int
    let der: Data
    let summary: CertificateSummary
    let sections: [FieldSection]
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
    case pkcs12
    case pkcs7
    case crl
    case notACertificate(fileName: String)

    var errorDescription: String? {
        switch self {
        case .empty:
            return "The file is empty."
        case .privateKey:
            return "This file contains a private key. CertRev only opens certificates."
        case .pkcs12:
            return "PKCS#12 files are not supported yet."
        case .pkcs7:
            return "PKCS#7 files are not supported yet."
        case .crl:
            return "Certificate revocation lists are not supported yet."
        case .notACertificate(let fileName):
            return "\(fileName) is not a certificate."
        }
    }
}
