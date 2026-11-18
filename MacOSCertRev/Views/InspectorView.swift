import SwiftUI

struct InspectorView: View {
    @Bindable var model: InspectorModel

    var body: some View {
        GeometryReader { proxy in
            HSplitView {
                if model.certificates.count > 1 {
                    certificateList
                        .frame(minWidth: 200, idealWidth: 240, maxWidth: 320)
                        .frame(maxHeight: .infinity)
                }
                inspectorColumn
                    .frame(maxWidth: .infinity, maxHeight: .infinity)
                    .layoutPriority(1)
            }
            .frame(width: proxy.size.width, height: proxy.size.height)
        }
    }

    /// The header keeps its own height. The certificate panel only gets the space
    /// below it, so a long subject or the sidebar cannot pull the panel up over the header.
    private var inspectorColumn: some View {
        VStack(spacing: 0) {
            summary
                .fixedSize(horizontal: false, vertical: true)
                .frame(maxWidth: .infinity, alignment: .topLeading)
                .background(Color(nsColor: .windowBackgroundColor))
                .zIndex(1)
            Divider()
            detail
                .frame(minWidth: 0, maxWidth: .infinity, minHeight: 0, maxHeight: .infinity)
                .layoutPriority(1)
                .clipped()
            Divider()
            PathView(report: model.trust)
                .frame(height: 148)
                .frame(maxWidth: .infinity)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .top)
    }

    private var certificateList: some View {
        List(selection: certificateSelection) {
            ForEach(model.certificates) { certificate in
                VStack(alignment: .leading, spacing: 2) {
                    Text(certificate.summary.commonName)
                        .lineLimit(1)
                    Text(certificate.summary.issuer)
                        .font(.caption)
                        .foregroundStyle(.secondary)
                        .lineLimit(1)
                    if let privateKey = certificate.privateKey {
                        Text("Private key: \(privateKey.description)")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                            .lineLimit(1)
                    }
                    if certificate.unchained {
                        Text("Doesn't chain")
                            .font(.caption)
                            .foregroundStyle(.orange)
                            .lineLimit(1)
                    }
                }
                .tag(certificate.id)
                .padding(.vertical, 2)
            }
        }
        .listStyle(.sidebar)
    }

    private var certificateSelection: Binding<Int?> {
        Binding(
            get: { model.selectedID },
            set: { model.selectCertificate($0) }
        )
    }

    @ViewBuilder
    private var summary: some View {
        if let certificate = model.selectedCertificate {
            VStack(alignment: .leading, spacing: 10) {
                summaryHeader(certificate)
                Grid(alignment: .topLeading, horizontalSpacing: 12, verticalSpacing: 5) {
                    summaryRow("Subject", certificate.summary.subject)
                    summaryRow("Issuer", certificate.summary.issuer)
                    summaryRow("Serial", certificate.summary.serialHex, monospaced: true)
                    summaryRow("Not Before", certificate.summary.notBefore.formatted(date: .abbreviated, time: .standard))
                    summaryRow("Not After", certificate.summary.notAfter.formatted(date: .abbreviated, time: .standard))
                    if let privateKey = certificate.privateKey {
                        summaryRow("Private Key", privateKey.description)
                    }
                    if certificate.unchained {
                        summaryRow("Chain", "Doesn't chain to another certificate in this file")
                    }
                }
            }
            .padding(.horizontal, 20)
            .padding(.vertical, 14)
            .frame(maxWidth: .infinity, alignment: .leading)
        }
    }

    private func summaryHeader(_ certificate: ParsedCertificate) -> some View {
        ViewThatFits(in: .horizontal) {
            HStack(alignment: .center, spacing: 12) {
                nameAndTrust(certificate)
                Spacer(minLength: 16)
                optionToggles
            }
            VStack(alignment: .leading, spacing: 8) {
                nameAndTrust(certificate)
                optionToggles
            }
        }
    }

    private func nameAndTrust(_ certificate: ParsedCertificate) -> some View {
        HStack(alignment: .firstTextBaseline, spacing: 8) {
            Text(certificate.summary.commonName)
                .font(.title2.bold())
                .textSelection(.enabled)
                .lineLimit(2)
            trustBadge
        }
    }

    private var optionToggles: some View {
        HStack(spacing: 16) {
            Toggle("Fetch intermediates", isOn: Binding(
                get: { model.fetchIntermediates },
                set: { model.setFetchIntermediates($0) }
            ))
            .toggleStyle(.switch)
            .controlSize(.small)
            .help("Allow trust evaluation to download missing intermediates")

            Button("Copy Certificate") {
                model.copyPEM()
            }
            .controlSize(.small)
            .help("Copy this certificate as -----BEGIN CERTIFICATE----- text")

            Toggle("View Text", isOn: Binding(
                get: { model.showsCertificateText },
                set: { show in
                    model.showsCertificateText = show
                    if show { model.showsRaw = false }
                }
            ))
            .toggleStyle(.switch)
            .controlSize(.small)
            .help("Show the -----BEGIN CERTIFICATE----- text")

            Toggle("RAW", isOn: Binding(
                get: { model.showsRaw },
                set: { show in
                    model.showsRaw = show
                    if show { model.showsCertificateText = false }
                }
            ))
            .toggleStyle(.switch)
            .controlSize(.small)
            .help("Show each field and its raw value")
        }
        .fixedSize(horizontal: true, vertical: false)
    }

    private func summaryRow(_ label: String, _ value: String, monospaced: Bool = false) -> some View {
        GridRow(alignment: .firstTextBaseline) {
            Text(label)
                .foregroundStyle(.secondary)
                .gridColumnAlignment(.trailing)
            Text(value)
                .font(monospaced ? .body.monospaced() : .body)
                .textSelection(.enabled)
                .fixedSize(horizontal: false, vertical: true)
                .frame(minWidth: 0, maxWidth: .infinity, alignment: .leading)
        }
    }

    @ViewBuilder
    private var trustBadge: some View {
        if let trust = model.trust {
            Text(trust.succeeded ? "Trusted" : "Untrusted")
                .font(.caption.weight(.semibold))
                .padding(.horizontal, 8)
                .padding(.vertical, 3)
                .background(trust.succeeded ? Color.green.opacity(0.18) : Color.red.opacity(0.16), in: Capsule())
        } else {
            Text("Checking")
                .font(.caption.weight(.semibold))
                .padding(.horizontal, 8)
                .padding(.vertical, 3)
                .background(.quaternary, in: Capsule())
        }
    }

    @ViewBuilder
    private var detail: some View {
        if model.showsRaw {
            FieldPane(model: model)
        } else if model.showsCertificateText, let pem = certificateText {
            ScrollView {
                Text(pem)
                    .font(.system(.body, design: .monospaced))
                    .textSelection(.enabled)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(20)
            }
            .frame(maxWidth: .infinity, minHeight: 0, maxHeight: .infinity)
        } else if let chain = systemChain {
            SystemCertificateView(chain: chain, networkFetchAllowed: model.fetchIntermediates)
                .frame(minWidth: 0, maxWidth: .infinity, minHeight: 0, maxHeight: .infinity)
        } else {
            FieldPane(model: model)
        }
    }

    private var systemChain: [Data]? {
        guard !model.certificates.isEmpty,
              let selectedID = model.selectedID,
              let leafIndex = model.certificates.firstIndex(where: { $0.id == selectedID })
        else { return nil }
        let ordered = TrustEvaluator.orderedCertificateDERs(model.certificates.map(\.der), leafIndex: leafIndex)
        return ordered.isEmpty ? nil : ordered
    }

    private var certificateText: String? {
        guard let der = model.selectedCertificate?.der else { return nil }
        return PEMEncoding.certificate(from: der)
    }
}
