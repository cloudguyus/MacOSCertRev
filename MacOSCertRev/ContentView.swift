import SwiftUI

struct ContentView: View {
    @Bindable var model: InspectorModel

    var body: some View {
        Group {
            if model.certificates.isEmpty {
                emptyState
            } else {
                InspectorView(model: model)
            }
        }
        .frame(minWidth: 880, minHeight: 520)
        .navigationTitle(model.fileName ?? "CertRev")
        .toolbar { toolbar }
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
    }

    private var emptyState: some View {
        VStack(spacing: 16) {
            Image(systemName: "checkmark.seal")
                .font(.system(size: 52))
                .foregroundStyle(.secondary)
            Text("Drop a certificate")
                .font(.title2)
            Text("PEM or DER (.pem, .cer, .crt, .der). The file stays in memory.")
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

    @ToolbarContentBuilder
    private var toolbar: some ToolbarContent {
        ToolbarItemGroup {
            Button("Open", systemImage: "folder") {
                model.openPanel()
            }
            .help("Open a certificate")

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
