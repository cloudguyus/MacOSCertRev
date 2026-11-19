import SwiftUI

struct ContentView: View {
    @Bindable var model: InspectorModel

    var body: some View {
        Group {
            if model.certificates.isEmpty {
                emptyState
                    .navigationTitle("CertRev")
                    .toolbar { InspectorToolbar(model: model) }
            } else {
                InspectorView(model: model)
            }
        }
        .frame(minWidth: 880, minHeight: 520)
        .dropDestination(for: URL.self) { urls, _ in
            guard let url = urls.first else { return false }
            model.load(url: url)
            return true
        }
        .alert(
            "Can't open certificate",
            isPresented: Binding(
                get: { model.errorMessage != nil },
                set: { if !$0 { model.errorMessage = nil } }
            )
        ) {
            Button("OK", role: .cancel) {}
        } message: {
            Text(model.errorMessage ?? "")
        }
        .onOpenURL { url in
            model.load(url: url)
        }
        .sheet(isPresented: $model.showsPasswordPrompt, onDismiss: {
            model.cancelPasswordPrompt()
        }) {
            PKCS12PasswordSheet(
                fileName: model.passwordPromptFileName ?? "PKCS#12",
                errorMessage: model.passwordPromptError,
                onOpen: { model.submitPKCS12Password($0) },
                onCancel: { model.cancelPasswordPrompt() }
            )
        }
    }

    private var emptyState: some View {
        VStack(spacing: 16) {
            Image(systemName: "checkmark.seal")
                .font(.system(size: 52))
                .foregroundStyle(.secondary)
            Text("Drop a certificate")
                .font(.title2)
            Text("PEM, DER, PKCS#12, or PKCS#7. A PKCS#12 password is requested and then discarded. The file stays in memory.")
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
            Button("Open…") {
                model.openPanel()
            }
            .keyboardShortcut("o")
            .buttonStyle(.borderedProminent)
        }
        .padding(40)
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }
}

/// Open and Copy stay at the trailing edge of the detail toolbar, clear of the title.
@MainActor
struct InspectorToolbar: ToolbarContent {
    @Bindable var model: InspectorModel

    var body: some ToolbarContent {
        ToolbarItemGroup(placement: .primaryAction) {
            Button("Open", systemImage: "folder") {
                model.openPanel()
            }
            .help("Open a certificate, PKCS#12, or PKCS#7 file")

            Button("Copy", systemImage: "doc.on.doc") {
                if model.showsRaw {
                    model.copySelectedField()
                } else {
                    model.copyPEM()
                }
            }
            .keyboardShortcut("c")
            .disabled(model.showsRaw ? model.selectedField == nil : model.certificates.isEmpty)
            .help(model.showsRaw ? "Copy the selected field" : "Copy this certificate as -----BEGIN CERTIFICATE----- text")
        }
    }
}
