import AppKit
import Foundation
import Observation
import UniformTypeIdentifiers

@MainActor
@Observable
final class InspectorModel {
    static let shared = InspectorModel(evaluateTrust: { @Sendable ders, leafIndex, options in
        await TrustEvaluator.evaluate(ders: ders, leafIndex: leafIndex, options: options)
    })

    private(set) var certificates: [ParsedCertificate] = []
    private(set) var fileName: String?
    private(set) var trust: TrustReport?
    var errorMessage: String?
    /// Shown while a PKCS#12 password is being requested. The password itself is not stored.
    var showsPasswordPrompt = false
    var passwordPromptFileName: String?
    var passwordPromptError: String?
    /// On shows CertRev's field list. Off shows the system view, unless certificate text is on.
    var showsRaw = false
    /// On shows the same `-----BEGIN CERTIFICATE-----` text that Copy Certificate copies.
    var showsCertificateText = false
    var fetchIntermediates = false
    var selectedID: Int?
    var selectedFieldID: String?

    private var trustGeneration = 0
    private var trustEvaluationTask: Task<Void, Never>?
    private let evaluateTrust: @Sendable ([Data], Int, TrustEvaluationOptions) async -> TrustReport
    /// The PKCS#12 bytes waiting on a password. Cleared when the prompt closes.
    private var pendingPKCS12: PendingPKCS12?

    private struct PendingPKCS12 {
        var data: Data
        var fileName: String
    }

    /// Tests pass a stand-in so a trust result can finish after a later open has already failed.
    init(
        evaluateTrust: @escaping @Sendable ([Data], Int, TrustEvaluationOptions) async -> TrustReport
    ) {
        self.evaluateTrust = evaluateTrust
    }

    var selectedCertificate: ParsedCertificate? {
        guard let selectedID else { return nil }
        return certificates.first { $0.id == selectedID }
    }

    var selectedField: FieldRow? {
        guard let selectedFieldID, let certificate = selectedCertificate else { return nil }
        return certificate.sections.lazy.flatMap(\.rows).first { $0.id == selectedFieldID }
    }

    func openPanel() {
        let panel = NSOpenPanel()
        panel.canChooseFiles = true
        panel.canChooseDirectories = false
        panel.allowsMultipleSelection = false
        panel.allowsOtherFileTypes = true
        panel.message = "Choose a PEM, DER, PKCS#12, or PKCS#7 file."
        panel.allowedContentTypes = Self.openPanelTypes()
        guard panel.runModal() == .OK, let url = panel.url else { return }
        load(url: url)
    }

    func load(url: URL) {
        let accessing = url.startAccessingSecurityScopedResource()
        defer {
            if accessing {
                url.stopAccessingSecurityScopedResource()
            }
        }
        let data: Data
        do {
            data = try Data(contentsOf: url)
        } catch {
            fail(error)
            return
        }
        let name = url.lastPathComponent
        if CertificateLoader.needsPassword(data: data, fileName: name) {
            pendingPKCS12 = PendingPKCS12(data: data, fileName: name)
            passwordPromptFileName = name
            passwordPromptError = nil
            showsPasswordPrompt = true
            return
        }
        dismissPasswordPrompt()
        ingest(data: data, fileName: name, password: nil, retryWrongPassword: false)
    }

    /// Imports the PKCS#12 that the password sheet is asking about.
    /// The password is not stored on the model. A wrong password leaves the sheet open.
    func submitPKCS12Password(_ password: String) {
        guard let pending = pendingPKCS12 else { return }
        ingest(data: pending.data, fileName: pending.fileName, password: password, retryWrongPassword: true)
    }

    func cancelPasswordPrompt() {
        dismissPasswordPrompt()
    }

    private func ingest(data: Data, fileName name: String, password: String?, retryWrongPassword: Bool) {
        do {
            let loaded = try CertificateLoader.load(data: data, fileName: name, password: password)
            let parsed = try loaded.enumerated().map { index, item in
                FieldDecoder.annotate(
                    try FieldDecoder.decode(der: item.der, index: index),
                    privateKey: item.privateKey,
                    unchained: item.unchained
                )
            }
            dismissPasswordPrompt()
            fileName = name
            certificates = parsed
            selectedID = parsed.first?.id
            selectedFieldID = parsed.first?.sections.first?.rows.first?.id
            errorMessage = nil
            trust = nil
            scheduleTrustEvaluation()
        } catch let error as CertificateLoadError where error == .pkcs12WrongPassword && retryWrongPassword {
            passwordPromptError = error.localizedDescription
        } catch {
            fail(error)
        }
    }

    private func dismissPasswordPrompt() {
        pendingPKCS12 = nil
        passwordPromptFileName = nil
        passwordPromptError = nil
        showsPasswordPrompt = false
    }

    private func fail(_ error: Error) {
        dismissPasswordPrompt()
        // Drop the certificate already on screen, and retire the evaluation in
        // flight so it cannot put that certificate's trust result back.
        trustGeneration += 1
        certificates = []
        fileName = nil
        selectedID = nil
        selectedFieldID = nil
        trust = nil
        errorMessage = error.localizedDescription
    }

    private static func openPanelTypes() -> [UTType] {
        let identifiers = [
            "com.cloudguyus.x509-certificate",
            "com.cloudguyus.pem-certificate",
            "com.rsa.pkcs-12",
            "com.rsa.pkcs-7",
        ]
        let extensions = ["cer", "crt", "der", "pem", "p12", "pfx", "p7b", "p7c"]
        var seen = Set<String>()
        var types: [UTType] = []
        for type in identifiers.compactMap({ UTType($0) }) + extensions.compactMap({ UTType(filenameExtension: $0) }) {
            if seen.insert(type.identifier).inserted {
                types.append(type)
            }
        }
        return types.isEmpty ? [.data] : types
    }

    func selectCertificate(_ id: Int?) {
        selectedID = id
        selectedFieldID = selectedCertificate?.sections.first?.rows.first?.id
        scheduleTrustEvaluation()
    }

    func setFetchIntermediates(_ allowed: Bool) {
        fetchIntermediates = allowed
        scheduleTrustEvaluation()
    }

    func copySelectedField() {
        guard let value = selectedField?.value else { return }
        writePasteboard(value)
    }

    func copyPEM() {
        guard let der = selectedCertificate?.der else { return }
        writePasteboard(PEMEncoding.certificate(from: der))
    }

    private func writePasteboard(_ value: String) {
        let pasteboard = NSPasteboard.general
        pasteboard.clearContents()
        pasteboard.setString(value, forType: .string)
    }

    /// Waits until the evaluation started by the latest successful open finishes.
    /// A failed open leaves that task in place so a test can see it decline to
    /// write a trust result for the certificate that was just cleared.
    func waitForTrustEvaluation() async {
        await trustEvaluationTask?.value
    }

    private func scheduleTrustEvaluation() {
        guard !certificates.isEmpty, let selectedID, let leafIndex = certificates.firstIndex(where: { $0.id == selectedID }) else {
            trust = nil
            return
        }
        trustGeneration += 1
        let generation = trustGeneration
        let ders = certificates.map(\.der)
        let options = TrustEvaluationOptions(
            networkFetchAllowed: fetchIntermediates,
            anchorDERs: nil
        )
        let evaluate = evaluateTrust
        trustEvaluationTask = Task {
            let report = await evaluate(ders, leafIndex, options)
            // A failed open advances `trustGeneration` and clears `certificates`.
            // Either one means this result belongs to a file that is no longer open.
            guard generation == trustGeneration, !certificates.isEmpty else { return }
            trust = report
        }
    }
}
