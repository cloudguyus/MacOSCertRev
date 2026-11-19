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

    func testBundleIntermediateIsRequiredForTrust() async throws {
        let chain = try CertificateFixtures.hierarchy()
        let options = TrustEvaluationOptions(networkFetchAllowed: false, anchorDERs: [chain.root])

        let leafAlone = await TrustEvaluator.evaluate(ders: [chain.leaf], leafIndex: 0, options: options)
        XCTAssertFalse(leafAlone.succeeded)
        XCTAssertFalse(leafAlone.message.isEmpty)

        let withIntermediate = await TrustEvaluator.evaluate(
            ders: [chain.leaf, chain.intermediate],
            leafIndex: 0,
            options: options
        )
        XCTAssertTrue(withIntermediate.succeeded, withIntermediate.message)
        XCTAssertGreaterThanOrEqual(withIntermediate.chain.count, 2)

        let reordered = TrustEvaluator.orderedCertificateDERs(
            [chain.intermediate, chain.leaf],
            leafIndex: 1
        )
        XCTAssertEqual(reordered, [chain.leaf, chain.intermediate])
        let selectedLeaf = await TrustEvaluator.evaluate(
            ders: [chain.intermediate, chain.leaf],
            leafIndex: 1,
            options: options
        )
        XCTAssertTrue(selectedLeaf.succeeded, selectedLeaf.message)
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
