import Foundation

enum PEMEncoding {
    /// PEM text for one certificate, with 64-character Base64 lines.
    static func certificate(from der: Data) -> String {
        let body = der.base64EncodedString(options: [.lineLength64Characters, .endLineWithLineFeed])
        return "-----BEGIN CERTIFICATE-----\n\(body)\n-----END CERTIFICATE-----\n"
    }
}
