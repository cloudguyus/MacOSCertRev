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
}
