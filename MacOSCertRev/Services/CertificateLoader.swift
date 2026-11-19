import Foundation
import Security
import SwiftASN1
import X509

enum CertificateLoader {
    /// PKCS#12 object identifiers live under 1.2.840.113549.1.12.
    private static let pkcs12OID = Data([0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x0C])
    /// PKCS#7 content types under 1.2.840.113549.1.7, other than id-data.
    private static let pkcs7OIDs = [
        Data([0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x02]),
        Data([0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x03]),
        Data([0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x04]),
        Data([0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x05]),
        Data([0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x06]),
    ]
    /// ASCII armor that opens every PEM block. Matched on the raw bytes so a
    /// non-UTF-8 comment cannot hide the certificate that follows.
    private static let pemBeginMarker = Data("-----BEGIN ".utf8)

    /// True when the bytes are a PKCS#12 PFX and opening them needs a password.
    /// A corrupt `.p12` returns false so the caller can show the corrupt-file error
    /// without asking for a password.
    static func needsPassword(data: Data, fileName: String) -> Bool {
        guard let payload = pkcs12DER(data: data, fileName: fileName) else { return false }
        return PKCS12Reader.looksLikeBundle(payload)
    }

    static func load(data: Data, fileName: String, password: String? = nil) throws -> [LoadedCertificate] {
        guard !data.isEmpty else { throw CertificateLoadError.empty }

        let lowered = fileName.lowercased()
        if lowered.hasSuffix(".crl") {
            throw CertificateLoadError.crl
        }

        if let payload = pkcs12DER(data: data, fileName: fileName) {
            guard PKCS12Reader.looksLikeBundle(payload) else {
                throw CertificateLoadError.pkcs12Corrupt
            }
            guard let password else { throw CertificateLoadError.pkcs12PasswordRequired }
            return try loadPKCS12(payload, password: password, fileName: fileName)
        }
        if shouldTreatAsPKCS7(data, fileName: fileName) {
            return try loadPKCS7(data, fileName: fileName)
        }

        if data.range(of: pemBeginMarker) != nil {
            guard let text = String(data: data, encoding: .utf8) ?? String(data: data, encoding: .isoLatin1) else {
                throw CertificateLoadError.notACertificate(fileName: fileName)
            }
            return try loadPEM(text, fileName: fileName)
        }
        return try loadDER(data, fileName: fileName)
    }

    private static func loadPKCS12(_ der: Data, password: String, fileName: String) throws -> [LoadedCertificate] {
        let imported = try PKCS12Reader.importBundle(der, password: password)
        guard !imported.isEmpty else { throw CertificateLoadError.pkcs12Corrupt }
        return try imported.map { item in
            guard let validated = try? validatedDER(item.der, fileName: fileName) else {
                throw CertificateLoadError.pkcs12Corrupt
            }
            return LoadedCertificate(der: validated, unchained: item.unchained, privateKey: item.privateKey)
        }
    }

    private static func loadPKCS7(_ data: Data, fileName: String) throws -> [LoadedCertificate] {
        let payloads = try pkcs7Payloads(data, fileName: fileName)
        var ders: [Data] = []
        for payload in payloads {
            let extracted = try PKCS7Reader.certificateDERs(from: payload)
            for der in extracted {
                do {
                    ders.append(try validatedDER(der, fileName: fileName))
                } catch {
                    throw CertificateLoadError.pkcs7Corrupt
                }
            }
        }
        let ordered: [CertificateChainOrder.Item]
        do {
            ordered = try CertificateChainOrder.order(ders)
        } catch {
            throw CertificateLoadError.pkcs7Corrupt
        }
        return ordered.map { LoadedCertificate(der: $0.der, unchained: $0.unchained) }
    }

    private static func pkcs12DER(data: Data, fileName: String) -> Data? {
        let named = isPKCS12Name(fileName)
        if data.range(of: pemBeginMarker) != nil {
            guard let text = String(data: data, encoding: .utf8) ?? String(data: data, encoding: .isoLatin1) else {
                return named ? data : nil
            }
            guard let block = pemBlocks(in: text).first(where: { $0.label.contains("PKCS12") || $0.label == "PFX" }) else {
                return nil
            }
            return Data(base64Encoded: block.base64, options: [.ignoreUnknownCharacters]) ?? data
        }
        if named { return data }
        if data.range(of: pkcs12OID) != nil, !isCertificate(data) {
            return data
        }
        return nil
    }

    private static func shouldTreatAsPKCS7(_ data: Data, fileName: String) -> Bool {
        if isPKCS7Name(fileName) { return true }
        if data.range(of: pemBeginMarker) != nil {
            guard let text = String(data: data, encoding: .utf8) ?? String(data: data, encoding: .isoLatin1) else {
                return false
            }
            return pemBlocks(in: text).contains { $0.label.contains("PKCS7") || $0.label == "CMS" }
        }
        if isCertificate(data) || data.range(of: pkcs12OID) != nil { return false }
        return pkcs7OIDs.contains { data.range(of: $0) != nil }
    }

    private static func pkcs7Payloads(_ data: Data, fileName: String) throws -> [Data] {
        guard data.range(of: pemBeginMarker) != nil else { return [data] }
        guard let text = String(data: data, encoding: .utf8) ?? String(data: data, encoding: .isoLatin1) else {
            throw CertificateLoadError.pkcs7Corrupt
        }
        let blocks = pemBlocks(in: text)
        if blocks.contains(where: { $0.label.contains("PRIVATE KEY") }) {
            throw CertificateLoadError.privateKey
        }
        let pkcs7 = blocks.filter { $0.label.contains("PKCS7") || $0.label == "CMS" }
        guard !pkcs7.isEmpty else { throw CertificateLoadError.pkcs7Corrupt }
        return try pkcs7.map { block in
            guard let decoded = Data(base64Encoded: block.base64, options: [.ignoreUnknownCharacters]) else {
                throw CertificateLoadError.pkcs7Corrupt
            }
            return decoded
        }
    }

    private static func isPKCS12Name(_ fileName: String) -> Bool {
        let lowered = fileName.lowercased()
        return lowered.hasSuffix(".p12") || lowered.hasSuffix(".pfx")
    }

    private static func isPKCS7Name(_ fileName: String) -> Bool {
        let lowered = fileName.lowercased()
        return lowered.hasSuffix(".p7b") || lowered.hasSuffix(".p7c")
    }

    private static func isCertificate(_ data: Data) -> Bool {
        (try? validatedDER(data, fileName: "certificate")) != nil
    }

    private static func loadPEM(_ text: String, fileName: String) throws -> [LoadedCertificate] {
        let blocks = pemBlocks(in: text)
        guard !blocks.isEmpty else { throw CertificateLoadError.notACertificate(fileName: fileName) }

        // Reject the whole file. The key bytes stay out of the error and the field model.
        if blocks.contains(where: { $0.label.contains("PRIVATE KEY") }) {
            throw CertificateLoadError.privateKey
        }
        if blocks.contains(where: { $0.label.contains("PKCS12") || $0.label == "PFX" }) {
            throw CertificateLoadError.pkcs12Corrupt
        }
        if blocks.contains(where: { $0.label.contains("PKCS7") || $0.label == "CMS" }) {
            throw CertificateLoadError.pkcs7Corrupt
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
            return LoadedCertificate(der: try validatedDER(der, fileName: fileName))
        }
    }

    private static func loadDER(_ data: Data, fileName: String) throws -> [LoadedCertificate] {
        if let der = try? validatedDER(data, fileName: fileName) {
            return [LoadedCertificate(der: der)]
        }
        if data.range(of: pkcs12OID) != nil {
            throw CertificateLoadError.pkcs12Corrupt
        }
        if pkcs7OIDs.contains(where: { data.range(of: $0) != nil }) {
            throw CertificateLoadError.pkcs7Corrupt
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
