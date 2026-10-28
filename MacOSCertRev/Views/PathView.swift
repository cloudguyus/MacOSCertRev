import SwiftUI

struct PathView: View {
    let report: TrustReport?

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 8) {
                Text("Certification Path")
                    .font(.headline)
                if let report {
                    Text(report.message)
                        .foregroundStyle(report.succeeded ? Color.primary : Color.red)
                        .textSelection(.enabled)
                    if report.chain.isEmpty {
                        Text("No chain was built.")
                            .foregroundStyle(.secondary)
                    } else {
                        ForEach(Array(report.chain.enumerated()), id: \.offset) { index, name in
                            HStack(alignment: .firstTextBaseline, spacing: 8) {
                                Text("\(index + 1)")
                                    .font(.caption.monospacedDigit())
                                    .foregroundStyle(.secondary)
                                    .frame(width: 16, alignment: .trailing)
                                Text(name)
                                    .textSelection(.enabled)
                            }
                        }
                    }
                } else {
                    HStack(spacing: 8) {
                        ProgressView()
                            .controlSize(.small)
                        Text("Evaluating trust…")
                            .foregroundStyle(.secondary)
                    }
                }
            }
            .padding(.horizontal, 20)
            .padding(.vertical, 12)
            .frame(maxWidth: .infinity, alignment: .leading)
        }
    }
}
