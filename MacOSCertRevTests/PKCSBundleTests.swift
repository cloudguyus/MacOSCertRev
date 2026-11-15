import Foundation
import XCTest
@testable import MacOSCertRev

final class PKCSBundleTests: XCTestCase {
    private let password = "test123"
    private let leaf = "CertRev Test Leaf"
    private let intermediate = "CertRev Test Intermediate CA"
    private let root = "CertRev Test Root CA"
    private let unrelated = "CertRev Test Unrelated"

    func testAES256PKCS12WithCorrectPassword() throws {
        let loaded = try open("leaf-aes256.p12", password: password)
        XCTAssertEqual(try names(loaded), [leaf])
        XCTAssertEqual(loaded.first?.privateKey, PrivateKeySummary(algorithm: "RSA", sizeBits: 2048))
        XCTAssertEqual(loaded.first?.unchained, false)
        try assertNoSecret(in: loaded)
    }

    func testWrongPasswordIsDistinctFromOtherPKCS12Errors() throws {
        let data = try PKCSFixtures.data("leaf-aes256.p12")
        XCTAssertThrowsError(try CertificateLoader.load(data: data, fileName: "leaf-aes256.p12", password: "wrong-password-value")) { error in
            XCTAssertEqual(error as? CertificateLoadError, .pkcs12WrongPassword)
            XCTAssertFalse(error.localizedDescription.contains("wrong-password-value"))
            XCTAssertFalse(error.localizedDescription.contains(password))
        }
    }

    func testMissingPasswordDoesNotImport() throws {
        let data = try PKCSFixtures.data("leaf-aes256.p12")
        XCTAssertTrue(CertificateLoader.needsPassword(data: data, fileName: "leaf-aes256.p12"))
        XCTAssertThrowsError(try CertificateLoader.load(data: data, fileName: "leaf-aes256.p12")) { error in
            XCTAssertEqual(error as? CertificateLoadError, .pkcs12PasswordRequired)
        }
    }

    func testEmptyPasswordPKCS12() throws {
        let loaded = try open("leaf-empty-password.p12", password: "")
        XCTAssertEqual(try names(loaded), [leaf])
        XCTAssertEqual(loaded.first?.privateKey?.description, "RSA 2048-bit")
        try assertNoSecret(in: loaded)

        let data = try PKCSFixtures.data("leaf-empty-password.p12")
        XCTAssertThrowsError(try CertificateLoader.load(data: data, fileName: "leaf-empty-password.p12", password: password)) { error in
            XCTAssertEqual(error as? CertificateLoadError, .pkcs12WrongPassword)
        }
    }

    func testLegacyEncryptionIsClassifiedSeparatelyFromThePassword() throws {
        let data = try PKCSFixtures.data("leaf-legacy-rc2-3des.p12")
        XCTAssertTrue(PKCS12Reader.usesLegacyEncryption(data))
        XCTAssertFalse(PKCS12Reader.usesLegacyEncryption(try PKCSFixtures.data("leaf-aes256.p12")))

        XCTAssertThrowsError(try CertificateLoader.load(data: data, fileName: "leaf-legacy-rc2-3des.p12", password: "wrong-password-value")) { error in
            XCTAssertEqual(error as? CertificateLoadError, .pkcs12WrongPassword)
            XCTAssertFalse(error.localizedDescription.contains("RC2"))
        }

        do {
            let loaded = try CertificateLoader.load(data: data, fileName: "leaf-legacy-rc2-3des.p12", password: password)
            XCTAssertEqual(try names(loaded), [leaf])
            XCTAssertNotNil(loaded.first?.privateKey)
            try assertNoSecret(in: loaded)
        } catch let error as CertificateLoadError {
            XCTAssertEqual(error, .pkcs12LegacyEncryption)
            XCTAssertTrue(error.localizedDescription.contains("RC2"))
            XCTAssertFalse(error.localizedDescription.contains(password))
        }
    }

    func testChainPKCS12OrderAndPrivateKeyOnlyOnTheLeaf() throws {
        for name in ["chain-aes256.p12", "chain-aes256.pfx"] {
            let loaded = try open(name, password: password)
            XCTAssertEqual(loaded.count, 3)
            guard loaded.count == 3 else { continue }
            XCTAssertEqual(try names(loaded), [leaf, intermediate, root])
            XCTAssertEqual(loaded[0].privateKey?.description, "RSA 2048-bit")
            XCTAssertNil(loaded[1].privateKey)
            XCTAssertNil(loaded[2].privateKey)
            XCTAssertTrue(loaded.allSatisfy { !$0.unchained })
            try assertNoSecret(in: loaded)
        }
    }

    func testCorruptPKCS12DoesNotAskForAPassword() throws {
        let data = try PKCSFixtures.data("corrupt.p12")
        XCTAssertFalse(CertificateLoader.needsPassword(data: data, fileName: "corrupt.p12"))
        XCTAssertThrowsError(try CertificateLoader.load(data: data, fileName: "corrupt.p12", password: password)) { error in
            XCTAssertEqual(error as? CertificateLoadError, .pkcs12Corrupt)
            XCTAssertFalse(error.localizedDescription.contains(password))
        }
    }

    func testPKCS7DERAndPEMBundleOrder() throws {
        for name in ["chain.p7b", "chain-pem.p7b"] {
            let loaded = try open(name)
            XCTAssertEqual(try names(loaded), [leaf, intermediate, root])
            XCTAssertTrue(loaded.allSatisfy { $0.privateKey == nil && !$0.unchained })
        }

        let der = try PKCSFixtures.data("chain.p7b")
        let asP7C = try CertificateLoader.load(data: der, fileName: "chain.p7c")
        XCTAssertEqual(try names(asP7C), [leaf, intermediate, root])

        let pem = try PKCSFixtures.data("chain-pem.p7b")
        let asPEM = try CertificateLoader.load(data: pem, fileName: "bundle.pem")
        XCTAssertEqual(try names(asPEM), [leaf, intermediate, root])
    }

    func testPKCS7FlagsTheCertificateThatDoesNotChain() throws {
        let loaded = try open("chain-plus-unchained.p7b")
        XCTAssertEqual(loaded.count, 4)
        let parsed = try parsed(loaded)
        let leafIndex = try XCTUnwrap(parsed.firstIndex { $0.summary.commonName == leaf })
        let intermediateIndex = try XCTUnwrap(parsed.firstIndex { $0.summary.commonName == intermediate })
        let rootIndex = try XCTUnwrap(parsed.firstIndex { $0.summary.commonName == root })
        XCTAssertLessThan(leafIndex, intermediateIndex)
        XCTAssertLessThan(intermediateIndex, rootIndex)
        let unchained = parsed.filter(\.unchained)
        XCTAssertEqual(unchained.map(\.summary.commonName), [unrelated])
        XCTAssertEqual(
            unchained.first?.sections.flatMap(\.rows).first { $0.title == "Chain" }?.value,
            "Doesn't chain to another certificate in this file"
        )
    }

    func testSignedAndEnvelopedPKCS7AreRejected() throws {
        for name in ["signed.p7b", "enveloped.p7b"] {
            let data = try PKCSFixtures.data(name)
            XCTAssertThrowsError(try CertificateLoader.load(data: data, fileName: name)) { error in
                XCTAssertEqual(error as? CertificateLoadError, .pkcs7NotACertificateBundle)
            }
        }
    }

    func testCorruptPKCS7() throws {
        let data = try PKCSFixtures.data("corrupt.p7b")
        XCTAssertThrowsError(try CertificateLoader.load(data: data, fileName: "corrupt.p7b")) { error in
            XCTAssertEqual(error as? CertificateLoadError, .pkcs7Corrupt)
        }
    }

    func testChainOrderDoesNotDependOnFileOrder() throws {
        let certificates = try ["root.crt", "intermediate.crt", "leaf.crt"].map { name in
            try CertificateLoader.load(data: try PKCSFixtures.data(name), fileName: name)[0].der
        }
        let ordered = try CertificateChainOrder.order(certificates)
        let orderedNames = try ordered.map { try FieldDecoder.decode(der: $0.der, index: 0).summary.commonName }
        XCTAssertEqual(orderedNames, [leaf, intermediate, root])
        XCTAssertTrue(ordered.allSatisfy { !$0.unchained })

        let withUnrelated = certificates + [try CertificateLoader.load(
            data: try PKCSFixtures.data("unrelated.crt"),
            fileName: "unrelated.crt"
        )[0].der]
        let mixed = try CertificateChainOrder.order(withUnrelated)
        XCTAssertEqual(mixed.filter(\.unchained).count, 1)
    }

    private func open(_ name: String, password: String? = nil) throws -> [LoadedCertificate] {
        try CertificateLoader.load(data: try PKCSFixtures.data(name), fileName: name, password: password)
    }

    private func parsed(_ loaded: [LoadedCertificate]) throws -> [ParsedCertificate] {
        try loaded.enumerated().map { index, item in
            FieldDecoder.annotate(
                try FieldDecoder.decode(der: item.der, index: index),
                privateKey: item.privateKey,
                unchained: item.unchained
            )
        }
    }

    private func names(_ loaded: [LoadedCertificate]) throws -> [String] {
        try parsed(loaded).map(\.summary.commonName)
    }

    private func assertNoSecret(in loaded: [LoadedCertificate]) throws {
        let parsed = try parsed(loaded)
        var text = loaded.map(\.description).joined(separator: "\n")
        text += "\n" + loaded.map(\.debugDescription).joined(separator: "\n")
        text += "\n" + parsed.map(\.privateKey?.description).compactMap { $0 }.joined(separator: "\n")
        text += "\n" + parsed.map(\.privateKey?.debugDescription).compactMap { $0 }.joined(separator: "\n")
        for certificate in parsed {
            for section in certificate.sections {
                text += "\n" + section.title
                for row in section.rows {
                    text += "\n" + row.title + "\n" + row.value + "\n" + (row.subtitle ?? "")
                }
            }
        }
        XCTAssertFalse(text.contains(password), "Password appeared in model text")
        XCTAssertFalse(text.contains("BEGIN PRIVATE KEY"), "Private key armor appeared in model text")
        XCTAssertFalse(text.contains("BEGIN RSA PRIVATE KEY"), "Private key armor appeared in model text")
        let key = try String(contentsOf: PKCSFixtures.url("TEST-ONLY-leaf.key.pem"), encoding: .utf8)
        let leaked = key.split(whereSeparator: \.isNewline).contains { line in
            line.count >= 40 && text.contains(line)
        }
        XCTAssertFalse(leaked, "Private key material appeared in model text")
    }
}

@MainActor
final class PKCS12PromptTests: XCTestCase {
    func testPasswordPromptThenImport() async throws {
        let model = InspectorModel(evaluateTrust: { @Sendable _, _, _ in
            TrustReport(succeeded: false, message: "not used", chain: [])
        })
        let certificate = try temporaryCertificate()
        defer { try? FileManager.default.removeItem(at: certificate.deletingLastPathComponent()) }

        model.load(url: certificate)
        await model.waitForTrustEvaluation()
        XCTAssertEqual(model.certificates.count, 1)

        model.load(url: PKCSFixtures.url("leaf-aes256.p12"))
        XCTAssertTrue(model.showsPasswordPrompt)
        XCTAssertEqual(model.passwordPromptFileName, "leaf-aes256.p12")
        XCTAssertNil(model.passwordPromptError)
        XCTAssertEqual(model.certificates.count, 1)
        XCTAssertNil(model.errorMessage)

        model.submitPKCS12Password("wrong-password-value")
        XCTAssertTrue(model.showsPasswordPrompt)
        XCTAssertEqual(model.passwordPromptError, CertificateLoadError.pkcs12WrongPassword.localizedDescription)
        XCTAssertEqual(model.fileName, "good.cer")
        XCTAssertEqual(model.certificates.count, 1)
        try assertModelDoesNotContain(model, "wrong-password-value")

        model.submitPKCS12Password("test123")
        await model.waitForTrustEvaluation()
        XCTAssertFalse(model.showsPasswordPrompt)
        XCTAssertNil(model.passwordPromptError)
        XCTAssertNil(model.passwordPromptFileName)
        XCTAssertNil(model.errorMessage)
        XCTAssertEqual(model.fileName, "leaf-aes256.p12")
        XCTAssertEqual(model.certificates.map(\.summary.commonName), ["CertRev Test Leaf"])
        XCTAssertEqual(model.certificates.first?.privateKey?.description, "RSA 2048-bit")
        let privateKeyRow = model.certificates.first?.sections.flatMap(\.rows).first { $0.id == "privateKey.present" }
        XCTAssertEqual(privateKeyRow?.value, "Yes")
        try assertModelDoesNotContain(model, "test123")
        try assertModelDoesNotContain(model, "BEGIN PRIVATE KEY")
    }

    func testCorruptPKCS12FailsWithoutAPrompt() async throws {
        let model = InspectorModel(evaluateTrust: { @Sendable _, _, _ in
            TrustReport(succeeded: false, message: "not used", chain: [])
        })
        model.load(url: PKCSFixtures.url("corrupt.p12"))
        XCTAssertFalse(model.showsPasswordPrompt)
        XCTAssertTrue(model.certificates.isEmpty)
        XCTAssertEqual(model.errorMessage, CertificateLoadError.pkcs12Corrupt.localizedDescription)
    }

    func testCancelPasswordPromptLeavesThePreviousCertificate() async throws {
        let model = InspectorModel(evaluateTrust: { @Sendable _, _, _ in
            TrustReport(succeeded: false, message: "not used", chain: [])
        })
        let certificate = try temporaryCertificate()
        defer { try? FileManager.default.removeItem(at: certificate.deletingLastPathComponent()) }
        model.load(url: certificate)
        await model.waitForTrustEvaluation()

        model.load(url: PKCSFixtures.url("leaf-aes256.p12"))
        model.cancelPasswordPrompt()
        XCTAssertFalse(model.showsPasswordPrompt)
        XCTAssertEqual(model.fileName, "good.cer")
        XCTAssertEqual(model.certificates.count, 1)
    }

    private func temporaryCertificate() throws -> URL {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("certrev-pkcs-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        let url = directory.appendingPathComponent("good.cer")
        try CertificateFixtures.leaf().write(to: url)
        return url
    }

    private func assertModelDoesNotContain(_ model: InspectorModel, _ secret: String) throws {
        let text = mirrorStrings(model).joined(separator: "\n")
        XCTAssertFalse(text.contains(secret), "Secret appeared on the inspector model")
        let key = try String(contentsOf: PKCSFixtures.url("TEST-ONLY-leaf.key.pem"), encoding: .utf8)
        let leaked = key.split(whereSeparator: \.isNewline).contains { line in
            line.count >= 40 && text.contains(line)
        }
        XCTAssertFalse(leaked, "Private key material appeared on the inspector model")
    }

    private func mirrorStrings(_ value: Any, depth: Int = 0) -> [String] {
        if depth > 8 { return [] }
        if let string = value as? String { return [string] }
        if value is Data { return [] }
        return Mirror(reflecting: value).children.flatMap { mirrorStrings($0.value, depth: depth + 1) }
    }
}

enum PKCSFixtures {
    static func url(_ name: String, sourceFile: String = #filePath) -> URL {
        let bundle = Bundle(for: PKCSBundleTests.self)
        let candidates = [
            bundle.url(forResource: name, withExtension: nil, subdirectory: "Fixtures/PKCS"),
            bundle.url(forResource: name, withExtension: nil, subdirectory: "PKCS"),
            bundle.url(forResource: name, withExtension: nil),
            URL(fileURLWithPath: sourceFile)
                .deletingLastPathComponent()
                .appendingPathComponent("Fixtures/PKCS")
                .appendingPathComponent(name),
        ]
        for candidate in candidates.compactMap({ $0 }) where FileManager.default.fileExists(atPath: candidate.path) {
            return candidate
        }
        preconditionFailure("Missing fixture \(name)")
    }

    static func data(_ name: String) throws -> Data {
        try Data(contentsOf: url(name))
    }
}
