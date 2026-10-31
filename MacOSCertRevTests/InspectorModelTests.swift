import Foundation
import XCTest
@testable import MacOSCertRev

@MainActor
final class InspectorModelTests: XCTestCase {
    func testFailedOpenClearsTheCertificateAlreadyOnScreen() async throws {
        let model = InspectorModel(evaluateTrust: { @Sendable _, _, _ in
            TrustReport(succeeded: true, message: "Evaluation succeeded.", chain: ["leaf.example"])
        })
        let fixture = try OpenFixture()
        defer { fixture.remove() }

        model.load(url: fixture.certificateURL)
        await model.waitForTrustEvaluation()

        XCTAssertEqual(model.fileName, "good.cer")
        XCTAssertEqual(model.certificates.count, 1)
        XCTAssertEqual(model.selectedCertificate?.summary.commonName, "leaf.example")
        XCTAssertNotNil(model.selectedID)
        XCTAssertNotNil(model.selectedFieldID)
        XCTAssertEqual(
            model.trust,
            TrustReport(succeeded: true, message: "Evaluation succeeded.", chain: ["leaf.example"])
        )
        XCTAssertNil(model.errorMessage)

        model.load(url: fixture.pkcs12URL)

        assertFailedOpen(model, error: .pkcs12)

        model.load(url: fixture.certificateURL)
        await model.waitForTrustEvaluation()
        XCTAssertEqual(model.fileName, "good.cer")
        XCTAssertEqual(model.certificates.count, 1)
        XCTAssertNil(model.errorMessage)
        XCTAssertEqual(model.trust?.succeeded, true)
    }

    func testFailedOpenIgnoresTrustEvaluationThatFinishesLater() async throws {
        let gate = TrustGate()
        defer { gate.release() }
        let model = InspectorModel(evaluateTrust: { @Sendable _, _, _ in
            await gate.wait()
            return TrustReport(succeeded: true, message: "late", chain: ["leaf.example"])
        })
        let fixture = try OpenFixture()
        defer { fixture.remove() }

        model.load(url: fixture.certificateURL)
        await gate.waitUntilEntered()

        XCTAssertEqual(model.fileName, "good.cer")
        XCTAssertEqual(model.certificates.count, 1)
        XCTAssertEqual(model.selectedCertificate?.summary.commonName, "leaf.example")
        XCTAssertNil(model.trust)

        model.load(url: fixture.privateKeyURL)
        assertFailedOpen(model, error: .privateKey)

        gate.release()
        await model.waitForTrustEvaluation()
        assertFailedOpen(model, error: .privateKey)
    }

    private func assertFailedOpen(
        _ model: InspectorModel,
        error: CertificateLoadError,
        file: StaticString = #filePath,
        line: UInt = #line
    ) {
        XCTAssertTrue(model.certificates.isEmpty, file: file, line: line)
        XCTAssertNil(model.fileName, file: file, line: line)
        XCTAssertNil(model.selectedID, file: file, line: line)
        XCTAssertNil(model.selectedFieldID, file: file, line: line)
        XCTAssertNil(model.trust, file: file, line: line)
        XCTAssertEqual(model.errorMessage, error.localizedDescription, file: file, line: line)
    }
}

private struct OpenFixture {
    let directory: URL
    let certificateURL: URL
    let pkcs12URL: URL
    let privateKeyURL: URL

    init() throws {
        directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("certrev-failed-open-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        certificateURL = directory.appendingPathComponent("good.cer")
        pkcs12URL = directory.appendingPathComponent("bag.p12")
        privateKeyURL = directory.appendingPathComponent("key.pem")
        try CertificateFixtures.leaf().write(to: certificateURL)
        try Data([0x30, 0x00]).write(to: pkcs12URL)
        let pem = """
        -----BEGIN PRIVATE KEY-----
        AAAA
        -----END PRIVATE KEY-----
        """
        try Data(pem.utf8).write(to: privateKeyURL)
    }

    func remove() {
        try? FileManager.default.removeItem(at: directory)
    }
}

/// Holds the trust evaluator inside `load` until the test has opened a file that fails.
private final class TrustGate: @unchecked Sendable {
    private let lock = NSLock()
    private var enteredContinuation: CheckedContinuation<Void, Never>?
    private var releaseContinuations: [CheckedContinuation<Void, Never>] = []
    private var didEnter = false
    private var didRelease = false

    func wait() async {
        await withCheckedContinuation { (continuation: CheckedContinuation<Void, Never>) in
            lock.lock()
            if didRelease {
                lock.unlock()
                continuation.resume()
                return
            }
            releaseContinuations.append(continuation)
            let entered = enteredContinuation
            didEnter = true
            enteredContinuation = nil
            lock.unlock()
            entered?.resume()
        }
    }

    func waitUntilEntered() async {
        await withCheckedContinuation { (continuation: CheckedContinuation<Void, Never>) in
            lock.lock()
            if didEnter {
                lock.unlock()
                continuation.resume()
                return
            }
            enteredContinuation = continuation
            lock.unlock()
        }
    }

    func release() {
        lock.lock()
        if didRelease {
            lock.unlock()
            return
        }
        didRelease = true
        let continuations = releaseContinuations
        releaseContinuations = []
        lock.unlock()
        for continuation in continuations {
            continuation.resume()
        }
    }
}
