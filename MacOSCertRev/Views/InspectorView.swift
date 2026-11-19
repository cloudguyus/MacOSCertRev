import SwiftUI

struct InspectorView: View {
    @Bindable var model: InspectorModel
    /// Visible width of the detail pane, from the split view, so subject text wraps instead of running past the edge.
    @State private var detailPaneWidth: CGFloat = 0

    var body: some View {
        if model.certificates.count > 1 {
            NavigationSplitView {
                certificateList
                    .navigationSplitViewColumnWidth(min: 220, ideal: 320, max: 420)
                    // The sidebar segment keeps the traffic lights only. The filename
                    // belongs to the detail column, so it cannot cross the divider.
                    .toolbar(removing: .title)
                    .background(SplitViewAutosave(name: "CertRevInspectorSplit"))
            } detail: {
                detailColumn
            }
            .navigationSplitViewStyle(.balanced)
        } else {
            detailColumn
        }
    }

    /// The certificate summary, system panel, and path. Unchanged aside from living
    /// in the detail column so the toolbar title is leading-aligned there.
    private var detailColumn: some View {
        GeometryReader { proxy in
            VStack(spacing: 0) {
                summary
                    .frame(
                        minWidth: 0,
                        maxWidth: detailPaneWidth > 1 ? detailPaneWidth : (proxy.size.width > 1 ? proxy.size.width : .infinity),
                        alignment: .topLeading
                    )
                Divider()
                detail
                    // A zero minimum stops the system certificate view's tall
                    // fitting size from pushing the summary out of the window.
                    .frame(minWidth: 0, maxWidth: .infinity, minHeight: 0, maxHeight: .infinity)
                    .clipped()
                Divider()
                PathView(report: model.trust)
                    .frame(height: 148)
            }
            // Height comes from this column. Width is the column's own width:
            // pinning it to the window draws it over the sidebar.
            .frame(minWidth: 0, maxWidth: .infinity)
            .frame(width: proxy.size.width, height: proxy.size.height, alignment: .top)
            .background(SplitSubviewWidth { width in
                if abs(width - detailPaneWidth) > 0.5 {
                    detailPaneWidth = width
                }
            })
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .navigationTitle(documentTitle)
        .background(DetailColumnTitle(title: documentTitle))
        .toolbar { InspectorToolbar(model: model) }
    }

    private var documentTitle: String {
        model.fileName ?? "CertRev"
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
                .lineLimit(nil)
                .multilineTextAlignment(.leading)
                .fixedSize(horizontal: false, vertical: true)
                .frame(minWidth: 0, maxWidth: .infinity, alignment: .leading)
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
                .lineLimit(nil)
                .multilineTextAlignment(.leading)
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
        } else if let der = model.selectedCertificate?.der {
            SystemCertificateView(der: der)
                .frame(minWidth: 0, maxWidth: .infinity, minHeight: 0, maxHeight: .infinity)
        } else {
            FieldPane(model: model)
        }
    }

    private var certificateText: String? {
        guard let der = model.selectedCertificate?.der else { return nil }
        return PEMEncoding.certificate(from: der)
    }
}

/// Remembers the sidebar divider in user defaults.
private struct SplitViewAutosave: NSViewRepresentable {
    var name: String

    func makeNSView(context: Context) -> NSView { NSView(frame: .zero) }

    func updateNSView(_ nsView: NSView, context: Context) {
        DispatchQueue.main.async {
            guard let split = nsView.enclosingSplitView(), split.autosaveName != name else { return }
            split.autosaveName = name
        }
    }
}

/// Reports the width the split view actually assigned to this column.
private struct SplitSubviewWidth: NSViewRepresentable {
    var onChange: (CGFloat) -> Void

    func makeNSView(context: Context) -> NSView { NSView(frame: .zero) }

    func updateNSView(_ nsView: NSView, context: Context) {
        DispatchQueue.main.async {
            var view: NSView? = nsView
            while let current = view {
                if current.superview is NSSplitView {
                    onChange(current.bounds.width)
                    return
                }
                view = current.superview
            }
        }
    }
}

private extension NSView {
    func enclosingSplitView() -> NSSplitView? {
        var view: NSView? = self
        while let current = view {
            if let split = current as? NSSplitView { return split }
            view = current.superview
        }
        return nil
    }

    func firstTextField(matching title: String) -> NSTextField? {
        for subview in subviews {
            if let field = subview as? NSTextField, field.stringValue == title {
                return field
            }
            if let found = subview.firstTextField(matching: title) {
                return found
            }
        }
        return nil
    }
}

/// Keeps the Window menu and Mission Control title on the filename, and truncates
/// the toolbar title in the middle when the detail column is narrow.
private struct DetailColumnTitle: NSViewRepresentable {
    var title: String

    func makeNSView(context: Context) -> DetailColumnTitleView {
        let view = DetailColumnTitleView(frame: .zero)
        view.title = title
        return view
    }

    func updateNSView(_ view: DetailColumnTitleView, context: Context) {
        view.title = title
    }
}

private final class DetailColumnTitleView: NSView {
    var title = "" {
        didSet {
            guard oldValue != title else { return }
            apply()
        }
    }

    override func viewDidMoveToWindow() {
        super.viewDidMoveToWindow()
        apply()
    }

    override func layout() {
        super.layout()
        applyTruncation()
    }

    private func apply() {
        guard let window, !title.isEmpty else { return }
        if window.title != title {
            window.title = title
        }
        applyTruncation()
    }

    private func applyTruncation() {
        guard let window, !title.isEmpty, let field = window.documentTitleField(matching: title) else { return }
        if field.maximumNumberOfLines != 1 {
            field.maximumNumberOfLines = 1
        }
        guard let cell = field.cell, cell.lineBreakMode != .byTruncatingMiddle else { return }
        cell.lineBreakMode = .byTruncatingMiddle
    }
}

private extension NSWindow {
    /// The toolbar title lives in the titlebar, next to the content view. Skip the
    /// content so a certificate field is not treated as the window title.
    func documentTitleField(matching title: String) -> NSTextField? {
        guard let frame = contentView?.superview else { return nil }
        for subview in frame.subviews where subview !== contentView {
            if let field = subview.firstTextField(matching: title) {
                return field
            }
        }
        return nil
    }
}
