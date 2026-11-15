import SwiftUI

/// Asks for a PKCS#12 password. The field is cleared before the password is handed back.
struct PKCS12PasswordSheet: View {
    let fileName: String
    let errorMessage: String?
    let onOpen: (String) -> Void
    let onCancel: () -> Void

    @State private var password = ""
    @FocusState private var focused: Bool

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            Text("Password for \(fileName)")
                .font(.headline)
            Text("The password is used to read the certificates and is then discarded. It is not saved, logged, or added to Keychain. Leave it blank if the file has no password.")
                .font(.callout)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
            SecureField("Password", text: $password)
                .focused($focused)
                .onSubmit(submit)
            if let errorMessage {
                Text(errorMessage)
                    .font(.callout)
                    .foregroundStyle(.red)
                    .fixedSize(horizontal: false, vertical: true)
            }
            HStack {
                Spacer()
                Button("Cancel", role: .cancel, action: cancel)
                    .keyboardShortcut(.cancelAction)
                Button("Open", action: submit)
                    .keyboardShortcut(.defaultAction)
                    .buttonStyle(.borderedProminent)
            }
        }
        .padding(20)
        .frame(width: 440)
        .onAppear { focused = true }
        .interactiveDismissDisabled(true)
    }

    private func submit() {
        let value = password
        password = ""
        onOpen(value)
    }

    private func cancel() {
        password = ""
        onCancel()
    }
}
