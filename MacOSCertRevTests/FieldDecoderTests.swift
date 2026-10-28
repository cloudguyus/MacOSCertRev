import XCTest
@testable import MacOSCertRev

final class FieldDecoderTests: XCTestCase {
    func testExtensionRowMarksCriticalSAN() throws {
        let parsed = try FieldDecoder.decode(der: try CertificateFixtures.leaf(), index: 0)
        let san = parsed.sections.flatMap(\.rows).first { $0.title == "Subject Alternative Name" }
        XCTAssertEqual(san?.subtitle?.hasPrefix("Critical"), false)
        XCTAssertTrue(san?.subtitle?.contains("2.5.29.17") ?? false)
        XCTAssertTrue(san?.value.contains("DNS: example.com") ?? false)
        XCTAssertTrue(san?.value.contains("Raw value") ?? false)

        let usage = parsed.sections.flatMap(\.rows).first { $0.title == "Key Usage" }
        XCTAssertTrue(usage?.subtitle?.hasPrefix("Critical") ?? false)
        XCTAssertTrue(usage?.value.contains("Digital Signature") ?? false)
    }
}
