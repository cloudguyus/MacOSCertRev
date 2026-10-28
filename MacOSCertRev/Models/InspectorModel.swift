import AppKit
import Foundation
import Observation
import UniformTypeIdentifiers

@MainActor
@Observable
final class InspectorModel {
    static let shared = InspectorModel()

    private(set) var certificates: [ParsedCertificate] = []
    private(set) var fileName: String?
    private(set) var trust: TrustReport?
    var errorMessage: String?
    /// On shows CertRev's field list. Off shows the system view, unless certificate text is on.
    var showsRaw = false
    /// On shows the same `-----BEGIN CERTIFICATE-----` text that Copy Certificate copies.
    var showsCertificateText = false
    var fetchIntermediates = false
    var selectedID: Int?
    var selectedFieldID: String?

    private var trustGeneration = 0

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
        panel.message = "Choose a PEM or DER certificate."
        let types = ["cer", "crt", "der", "pem"].compactMap { UTType(filenameExtension: $0) }
        panel.allowedContentTypes = types.isEmpty ? [.data] : types
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
        do {
            let data = try Data(contentsOf: url)
            let ders = try CertificateLoader.load(data: data, fileName: url.lastPathComponent)
            let parsed = try ders.enumerated().map { index, der in
                try FieldDecoder.decode(der: der, index: index)
            }
            fileName = url.lastPathComponent
            certificates = parsed
            selectedID = parsed.first?.id
            selectedFieldID = parsed.first?.sections.first?.rows.first?.id
            errorMessage = nil
            trust = nil
            scheduleTrustEvaluation()
        } catch {
            errorMessage = error.localizedDescription
        }
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
        Task {
            let report = await TrustEvaluator.evaluate(ders: ders, leafIndex: leafIndex, options: options)
            guard generation == trustGeneration else { return }
            trust = report
        }
    }
}
