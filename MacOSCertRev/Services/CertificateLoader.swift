import Foundation
import Security
import SwiftASN1
import X509

enum CertificateLoader {
    /// PKCS#12 object identifiers live under 1.2.840.113549.1.12.
    private static let pkcs12OID = Data([0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x0C])
    /// PKCS#7 signedData is 1.2.840.113549.1.7.2.
    private static let pkcs7SignedDataOID = Data([0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x02])

    static func load(data: Data, fileName: String) throws -> [Data] {
        guard !data.isEmpty else { throw CertificateLoadError.empty }

        let lowered = fileName.lowercased()
        if lowered.hasSuffix(".pfx") || lowered.hasSuffix(".p12") {
            throw CertificateLoadError.pkcs12
        }
        if lowered.hasSuffix(".p7b") || lowered.hasSuffix(".p7c") {
            throw CertificateLoadError.pkcs7
        }
        if lowered.hasSuffix(".crl") {
            throw CertificateLoadError.crl
        }

        if let text = String(data: data, encoding: .utf8), text.contains("-----BEGIN ") {
            return try loadPEM(text, fileName: fileName)
        }
        return try loadDER(data, fileName: fileName)
    }

    private static func loadPEM(_ text: String, fileName: String) throws -> [Data] {
        let blocks = pemBlocks(in: text)
        guard !blocks.isEmpty else { throw CertificateLoadError.notACertificate(fileName: fileName) }

        // Reject the whole file. The key bytes stay out of the error and the field model.
        if blocks.contains(where: { $0.label.contains("PRIVATE KEY") }) {
            throw CertificateLoadError.privateKey
        }
        if blocks.contains(where: { $0.label.contains("PKCS12") || $0.label == "PFX" }) {
            throw CertificateLoadError.pkcs12
        }
        if blocks.contains(where: { $0.label.contains("PKCS7") || $0.label == "CMS" }) {
            throw CertificateLoadError.pkcs7
        }
        if blocks.contains(where: { $0.label.contains("CRL") }) {
            throw CertificateLoadError.crl
        }

        let certificateBlocks = blocks.filter {
            $0.label == "CERTIFICATE" || $0.label == "X509 CERTIFICATE" || $0.label == "TRUSTED CERTIFICATE"
        }
        guard !certificateBlocks.isEmpty else {
            throw CertificateLoadError.notACertificate(fileName: fileName)
        }

        return try certificateBlocks.map { block in
            guard let der = Data(base64Encoded: block.base64, options: [.ignoreUnknownCharacters]) else {
                throw CertificateLoadError.notACertificate(fileName: fileName)
            }
            return try validatedDER(der, fileName: fileName)
        }
    }

    private static func loadDER(_ data: Data, fileName: String) throws -> [Data] {
        if let der = try? validatedDER(data, fileName: fileName) {
            return [der]
        }
        if data.range(of: pkcs12OID) != nil {
            throw CertificateLoadError.pkcs12
        }
        if data.range(of: pkcs7SignedDataOID) != nil {
            throw CertificateLoadError.pkcs7
        }
        throw CertificateLoadError.notACertificate(fileName: fileName)
    }

    private static func validatedDER(_ data: Data, fileName: String) throws -> Data {
        do {
            _ = try Certificate(derEncoded: Array(data))
        } catch {
            throw CertificateLoadError.notACertificate(fileName: fileName)
        }
        guard SecCertificateCreateWithData(nil, data as CFData) != nil else {
            throw CertificateLoadError.notACertificate(fileName: fileName)
        }
        return data
    }

    private struct PEMBlock {
        var label: String
        var base64: String
    }

    private static func pemBlocks(in text: String) -> [PEMBlock] {
        var blocks: [PEMBlock] = []
        var label: String?
        var body: [String] = []
        for lineSub in text.split(whereSeparator: \.isNewline) {
            let line = lineSub.trimmingCharacters(in: .whitespaces)
            if line.hasPrefix("-----BEGIN "), line.hasSuffix("-----") {
                let start = line.index(line.startIndex, offsetBy: "-----BEGIN ".count)
                let end = line.index(line.endIndex, offsetBy: -"-----".count)
                label = String(line[start..<end]).uppercased()
                body = []
            } else if line.hasPrefix("-----END "), label != nil {
                blocks.append(PEMBlock(label: label ?? "", base64: body.joined()))
                label = nil
                body = []
            } else if label != nil {
                body.append(line)
            }
        }
        return blocks
    }
}
