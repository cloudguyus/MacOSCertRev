import XCTest
@testable import MacOSCertRev

final class CertificateLoaderTests: XCTestCase {
    func testPEMAndDERRoundTrip() throws {
        let der = try CertificateFixtures.leaf()
        let fromDER = try CertificateLoader.load(data: der, fileName: "leaf.cer")
        let fromPEM = try CertificateLoader.load(data: Data(CertificateFixtures.pem(der).utf8), fileName: "leaf.pem")

        XCTAssertEqual(fromDER, [der])
        XCTAssertEqual(fromPEM, [der])

        let parsed = try FieldDecoder.decode(der: fromPEM[0], index: 0)
        XCTAssertEqual(parsed.summary.commonName, "leaf.example")
        let values = parsed.sections.flatMap(\.rows).map(\.value).joined(separator: "\n")
        XCTAssertTrue(values.contains("DNS: example.com"))
        let pem = PEMEncoding.certificate(from: der)
        XCTAssertEqual(parsed.sections.last?.rows.last?.value, pem)
        XCTAssertEqual(try CertificateLoader.load(data: Data(pem.utf8), fileName: "encoded.pem"), [der])
        XCTAssertTrue(values.contains("Digital Signature"))
        XCTAssertTrue(values.contains("leaf.example"))
    }

    func testPEMBundleKeepsOrder() throws {
        let first = try CertificateFixtures.leaf(commonName: "one.example", serial: 11)
        let second = try CertificateFixtures.leaf(commonName: "two.example", serial: 12)
        let pem = CertificateFixtures.pem(first) + "\n" + CertificateFixtures.pem(second)
        let ders = try CertificateLoader.load(data: Data(pem.utf8), fileName: "bundle.pem")

        XCTAssertEqual(ders.count, 2)
        let parsed = try ders.enumerated().map { try FieldDecoder.decode(der: $1, index: $0) }
        XCTAssertEqual(parsed.map(\.summary.commonName), ["one.example", "two.example"])
    }

    func testPrivateKeyIsRejectedWithoutEchoingMaterial() {
        let secret = "SUPERSECRETKEYMATERIAL"
        let pem = """
        -----BEGIN PRIVATE KEY-----
        \(secret)
        -----END PRIVATE KEY-----
        """
        XCTAssertThrowsError(try CertificateLoader.load(data: Data(pem.utf8), fileName: "key.pem")) { error in
            XCTAssertEqual(error as? CertificateLoadError, .privateKey)
            XCTAssertFalse((error as? LocalizedError)?.errorDescription?.contains(secret) ?? true)
        }
    }

    func testPKCS12BlobIsRejected() {
        var data = Data([0x30, 0x10])
        data.append(contentsOf: [0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x0C, 0x01])
        XCTAssertThrowsError(try CertificateLoader.load(data: data, fileName: "bag.der")) { error in
            XCTAssertEqual(error as? CertificateLoadError, .pkcs12)
        }
    }

    func testTrustedCertificateWithoutAuxDataLoads() throws {
        let der = try CertificateFixtures.leaf()
        let pem = CertificateFixtures.trustedPEM(der)
        let loaded = try CertificateLoader.load(data: Data(pem.utf8), fileName: "trusted.pem")

        XCTAssertEqual(loaded, [der])
        let parsed = try FieldDecoder.decode(der: loaded[0], index: 0)
        XCTAssertEqual(parsed.summary.commonName, "leaf.example")

        // The label is case-insensitive. The -----BEGIN / -----END markers are not.
        let lowercaseLabel = pem.replacingOccurrences(of: "TRUSTED CERTIFICATE", with: "trusted certificate")
        XCTAssertEqual(try CertificateLoader.load(data: Data(lowercaseLabel.utf8), fileName: "trusted.pem"), [der])
    }

    func testTrustedCertificateWithAuxDataLoads() throws {
        let der = try CertificateFixtures.leaf()
        let pem = CertificateFixtures.trustedPEM(der, aux: CertificateFixtures.serverAuthTrustAux)
        let loaded = try CertificateLoader.load(data: Data(pem.utf8), fileName: "trusted.pem")

        XCTAssertEqual(loaded, [der])
        let parsed = try FieldDecoder.decode(der: loaded[0], index: 0)
        XCTAssertEqual(parsed.summary.commonName, "leaf.example")

        let withJunk = CertificateFixtures.trustedPEM(
            der,
            aux: CertificateFixtures.serverAuthTrustAux + Data([0xFF, 0x00, 0x99])
        )
        XCTAssertEqual(try CertificateLoader.load(data: Data(withJunk.utf8), fileName: "trusted.pem"), [der])
    }

    func testMixedCertificateAndTrustedBlocksKeepOrder() throws {
        let first = try CertificateFixtures.leaf(commonName: "one.example", serial: 11)
        let second = try CertificateFixtures.leaf(commonName: "two.example", serial: 12)
        let third = try CertificateFixtures.leaf(commonName: "three.example", serial: 13)
        let pem = CertificateFixtures.trustedPEM(first)
            + CertificateFixtures.pem(second)
            + CertificateFixtures.trustedPEM(third, aux: CertificateFixtures.serverAuthTrustAux)
        let ders = try CertificateLoader.load(data: Data(pem.utf8), fileName: "bundle.pem")

        XCTAssertEqual(ders, [first, second, third])
        let names = try ders.enumerated().map { try FieldDecoder.decode(der: $1, index: $0).summary.commonName }
        XCTAssertEqual(names, ["one.example", "two.example", "three.example"])
    }

    func testMalformedTrustedCertificateFailsCleanly() {
        let bodies: [Data] = [
            Data(),
            Data([0x30, 0x05]),
            Data([0x30, 0x7F]),
            Data([0x30, 0x80, 0x00, 0x00]),
            Data([0x04, 0x01, 0x00]),
            Data([0x30, 0x84, 0x7F, 0xFF, 0xFF, 0xFF]),
            Data([0x30, 0x03, 0x01, 0x01, 0xFF]),
            CertificateFixtures.serverAuthTrustAux,
            Data("not a certificate".utf8),
        ]
        for body in bodies {
            let pem = CertificateFixtures.trustedPEM(body: body)
            XCTAssertThrowsError(try CertificateLoader.load(data: Data(pem.utf8), fileName: "trusted.pem")) { error in
                XCTAssertEqual(error as? CertificateLoadError, .notACertificate(fileName: "trusted.pem"))
            }
        }

        var truncated = Data([0xE9, 0x0A])
        truncated.append(contentsOf: Data("-----BEGIN TRUSTED CERTIFICATE-----\nAAAA\n".utf8))
        XCTAssertThrowsError(try CertificateLoader.load(data: truncated, fileName: "trusted.pem")) { error in
            XCTAssertEqual(error as? CertificateLoadError, .notACertificate(fileName: "trusted.pem"))
        }
    }

    func testTrailingBytesStillRejectNormalPEMAndDER() throws {
        let der = try CertificateFixtures.leaf()
        var extra = der
        extra.append(CertificateFixtures.serverAuthTrustAux)

        XCTAssertThrowsError(try CertificateLoader.load(data: extra, fileName: "leaf.cer")) { error in
            XCTAssertEqual(error as? CertificateLoadError, .notACertificate(fileName: "leaf.cer"))
        }
        let pem = CertificateFixtures.pem(extra)
        XCTAssertThrowsError(try CertificateLoader.load(data: Data(pem.utf8), fileName: "leaf.pem")) { error in
            XCTAssertEqual(error as? CertificateLoadError, .notACertificate(fileName: "leaf.pem"))
        }
    }

    func testPEMWithLatin1HeaderCommentLoads() throws {
        let der = try CertificateFixtures.leaf()
        var data = Data("Subject: Caf".utf8)
        data.append(0xE9)
        data.append(0x0A)
        data.append(contentsOf: Data(CertificateFixtures.pem(der).utf8))
        data.append(0xE9)
        XCTAssertNil(String(data: data, encoding: .utf8))

        let loaded = try CertificateLoader.load(data: data, fileName: "latin1.pem")
        XCTAssertEqual(loaded, [der])
        let parsed = try FieldDecoder.decode(der: loaded[0], index: 0)
        XCTAssertEqual(parsed.summary.commonName, "leaf.example")
    }

    func testPEMBundleWithLatin1BytesBetweenCertificatesKeepsOrder() throws {
        let first = try CertificateFixtures.leaf(commonName: "one.example", serial: 11)
        let second = try CertificateFixtures.leaf(commonName: "two.example", serial: 12)
        var data = Data(CertificateFixtures.pem(first).utf8)
        data.append(0xE9)
        data.append(contentsOf: Data("\n".utf8))
        data.append(contentsOf: Data(CertificateFixtures.pem(second).utf8))
        XCTAssertNil(String(data: data, encoding: .utf8))

        let ders = try CertificateLoader.load(data: data, fileName: "bundle.pem")
        XCTAssertEqual(ders, [first, second])
        let names = try ders.enumerated().map { try FieldDecoder.decode(der: $1, index: $0).summary.commonName }
        XCTAssertEqual(names, ["one.example", "two.example"])
    }

    func testPEMWithUTF8CommentStillLoads() throws {
        let der = try CertificateFixtures.leaf()
        let text = "Subject: Café\n" + CertificateFixtures.pem(der)
        let data = Data(text.utf8)
        XCTAssertNotNil(String(data: data, encoding: .utf8))
        XCTAssertEqual(try CertificateLoader.load(data: data, fileName: "utf8.pem"), [der])
    }

    func testDERContainingHyphenRunLoadsAsDER() throws {
        let der = try CertificateFixtures.leaf(commonName: "leaf-----example")
        XCTAssertNotNil(der.range(of: Data("-----".utf8)))
        XCTAssertNil(der.range(of: Data("-----BEGIN ".utf8)))

        XCTAssertEqual(try CertificateLoader.load(data: der, fileName: "odd.cer"), [der])
        XCTAssertEqual(try CertificateLoader.load(data: der, fileName: "odd.pem"), [der])
        let parsed = try FieldDecoder.decode(der: der, index: 0)
        XCTAssertEqual(parsed.summary.commonName, "leaf-----example")
    }

    func testPrivateKeyWithNonUTF8BytesIsRejected() {
        let secret = "SUPERSECRETKEYMATERIAL"
        var data = Data([0xE9, 0x0A])
        data.append(contentsOf: Data("""
        -----BEGIN PRIVATE KEY-----
        \(secret)
        -----END PRIVATE KEY-----
        """.utf8))
        XCTAssertNil(String(data: data, encoding: .utf8))
        XCTAssertThrowsError(try CertificateLoader.load(data: data, fileName: "key.pem")) { error in
            XCTAssertEqual(error as? CertificateLoadError, .privateKey)
            XCTAssertFalse((error as? LocalizedError)?.errorDescription?.contains(secret) ?? true)
        }
    }
}
