import Security
import SwiftUI

struct InspectorView: View {
    @Bindable var model: InspectorModel

    var body: some View {
        GeometryReader { proxy in
            HSplitView {
                if model.certificates.count > 1 {
                    certificateList
                        .frame(minWidth: 200, idealWidth: 240, maxWidth: 320)
                        .frame(height: proxy.size.height)
                }
                VStack(spacing: 0) {
                    summary
                    Divider()
                    detail
                        // A zero minimum stops the system certificate view's tall
                        // fitting size from pushing the summary out of the window.
                        .frame(minHeight: 0, maxHeight: .infinity)
                        .frame(maxWidth: .infinity)
                        .clipped()
                    Divider()
                    PathView(report: model.trust)
                        .frame(height: 148)
                }
                .frame(width: proxy.size.width, height: proxy.size.height, alignment: .top)
            }
            .frame(width: proxy.size.width, height: proxy.size.height, alignment: .top)
        }
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
                .frame(maxWidth: .infinity, alignment: .leading)
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
        } else if let certificate = securityCertificate {
            SystemCertificateView(certificate: certificate)
                .frame(maxWidth: .infinity, maxHeight: .infinity)
        } else {
            FieldPane(model: model)
        }
    }

    private var securityCertificate: SecCertificate? {
        guard let der = model.selectedCertificate?.der else { return nil }
        return SecCertificateCreateWithData(nil, der as CFData)
    }

    private var certificateText: String? {
        guard let der = model.selectedCertificate?.der else { return nil }
        return PEMEncoding.certificate(from: der)
    }
}
