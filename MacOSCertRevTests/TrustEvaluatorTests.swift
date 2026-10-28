import XCTest
@testable import MacOSCertRev

final class TrustEvaluatorTests: XCTestCase {
    func testExplicitAnchorSucceeds() async throws {
        let der = try CertificateFixtures.authority()
        let report = await TrustEvaluator.evaluate(
            ders: [der],
            leafIndex: 0,
            options: TrustEvaluationOptions(networkFetchAllowed: false, anchorDERs: [der])
        )
        XCTAssertTrue(report.succeeded, report.message)
        XCTAssertFalse(report.chain.isEmpty)
    }

    func testEmptyAnchorSetFails() async throws {
        let der = try CertificateFixtures.authority()
        let report = await TrustEvaluator.evaluate(
            ders: [der],
            leafIndex: 0,
            options: TrustEvaluationOptions(networkFetchAllowed: false, anchorDERs: [])
        )
        XCTAssertFalse(report.succeeded)
        XCTAssertFalse(report.message.isEmpty)
    }
}
