import Foundation
import Security
import SwiftASN1
import X509

enum CertificateLoader {
    /// PKCS#12 object identifiers live under 1.2.840.113549.1.12.
    private static let pkcs12OID = Data([0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x0C])
    /// PKCS#7 signedData is 1.2.840.113549.1.7.2.
    private static let pkcs7SignedDataOID = Data([0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x02])
    /// ASCII armor that opens every PEM block. Matched on the raw bytes so a
    /// non-UTF-8 comment cannot hide the certificate that follows.
    private static let pemBeginMarker = Data("-----BEGIN ".utf8)

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

        // Armor is ASCII, but bytes outside it may not be UTF-8 (a Latin-1 comment
        // is enough to fail `String(encoding: .utf8)`). Detect the marker first.
        if data.range(of: pemBeginMarker) != nil {
            guard let text = String(data: data, encoding: .utf8) ?? String(data: data, encoding: .isoLatin1) else {
                throw CertificateLoadError.notACertificate(fileName: fileName)
            }
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
            guard let decoded = Data(base64Encoded: block.base64, options: [.ignoreUnknownCharacters]) else {
                throw CertificateLoadError.notACertificate(fileName: fileName)
            }
            // OpenSSL's TRUSTED CERTIFICATE is the certificate SEQUENCE with an
            // optional X509_CERT_AUX value concatenated after it. `Certificate`
            // rejects those trailing bytes, so keep only the leading SEQUENCE.
            let der: Data
            if block.label == "TRUSTED CERTIFICATE" {
                der = try leadingCertificateDER(decoded, fileName: fileName)
            } else {
                der = decoded
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

    /// The leading certificate inside an OpenSSL trusted-certificate value.
    ///
    /// `DER.parse` requires its input to be a single ASN.1 value, so it cannot
    /// be asked for this length while the aux data is still attached. The outer
    /// tag and length are read here, and `validatedDER` checks the slice.
    private static func leadingCertificateDER(_ data: Data, fileName: String) throws -> Data {
        guard let length = leadingDERSequenceLength(data) else {
            throw CertificateLoadError.notACertificate(fileName: fileName)
        }
        return Data(data.prefix(length))
    }

    /// Byte count of the first DER SEQUENCE, including its tag and length octets.
    /// Trailing bytes are allowed. Returns nil when the header is not a
    /// well-formed definite-length SEQUENCE contained in `data`.
    private static func leadingDERSequenceLength(_ data: Data) -> Int? {
        let bytes = [UInt8](data)
        guard bytes.count >= 2, bytes[0] == 0x30 else { return nil }

        let lengthOctet = bytes[1]
        if lengthOctet < 0x80 {
            let total = 2 + Int(lengthOctet)
            guard total <= bytes.count else { return nil }
            return total
        }

        // 0x80 is indefinite length, which DER does not use. Four length octets
        // cover any certificate and keep the accumulator inside Int.
        let lengthByteCount = Int(lengthOctet & 0x7F)
        guard (1...4).contains(lengthByteCount) else { return nil }
        let header = 2 + lengthByteCount
        guard bytes.count >= header, bytes[2] != 0 else { return nil }

        var contentLength = 0
        for byte in bytes[2..<header] {
            contentLength = (contentLength << 8) | Int(byte)
        }
        guard contentLength >= 0x80, contentLength <= bytes.count - header else { return nil }
        return header + contentLength
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
