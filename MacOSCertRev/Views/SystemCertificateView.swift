import Security
import SecurityInterface
import SwiftUI

struct SystemCertificateView: NSViewRepresentable {
    /// Leaf first, then the other certificates from the same file.
    var chain: [Data]
    var networkFetchAllowed: Bool

    func makeNSView(context: Context) -> CertificateScrollView {
        let scroll = CertificateScrollView()
        configure(scroll)
        return scroll
    }

    func updateNSView(_ scroll: CertificateScrollView, context: Context) {
        guard scroll.configuredChain != chain || scroll.configuredNetworkFetch != networkFetchAllowed else { return }
        configure(scroll)
        scroll.invalidateMeasurement()
        scroll.layoutSubtreeIfNeeded()
    }

    /// Take the space SwiftUI offers. The certificate panel's own fitting size is
    /// tall enough to cover the header when the subject wraps or a sidebar is open.
    func sizeThatFits(_ proposal: ProposedViewSize, nsView: CertificateScrollView, context: Context) -> CGSize? {
        CGSize(width: finite(proposal.width, fallback: 640), height: finite(proposal.height, fallback: 480))
    }

    private func finite(_ value: CGFloat?, fallback: CGFloat) -> CGFloat {
        guard let value, value.isFinite, value > 1 else { return fallback }
        return value
    }

    private func configure(_ scroll: CertificateScrollView) {
        let view = scroll.certificateView
        guard let leafDER = chain.first, let leaf = SecCertificateCreateWithData(nil, leafDER as CFData) else { return }
        let policy = SecPolicyCreateBasicX509()
        view.setPolicies(policy)
        view.setCertificate(leaf)
        view.setDisplayDetails(true)
        view.setDetailsDisclosed(true)
        view.setDisplayTrust(true)
        // Trust editing writes the user's trust settings. This app only inspects.
        view.setEditableTrust(false)
        // setCertificate builds a trust from the leaf alone. Replace it with the
        // same chain and basic policy the badge uses, so the two results agree.
        if chain.count > 1 {
            let index = chain.firstIndex(of: leafDER) ?? 0
            let trust = TrustEvaluator.makeTrust(
                ders: chain,
                leafIndex: index,
                options: TrustEvaluationOptions(
                    networkFetchAllowed: networkFetchAllowed,
                    anchorDERs: nil
                )
            )
            if let trust {
                scroll.displayedTrust = trust
                _ = SecTrustEvaluateWithError(trust, nil)
                apply(trust, to: view)
            }
        }
        scroll.configuredChain = chain
        scroll.configuredNetworkFetch = networkFetchAllowed
    }

    /// `SFCertificateView` has no public chain setter. `setTrust:` is what the
    /// panel uses internally to display a trust result for more than one certificate.
    private func apply(_ trust: SecTrust, to view: SFCertificateView) {
        let selectors = ["setTrust:", "_setTrust:"].map(NSSelectorFromString.init)
        guard let selector = selectors.first(where: { view.responds(to: $0) }) else { return }
        view.perform(selector, with: trust)
    }
}

/// `SFCertificateView` reports a tall fitting size. Hosting it directly makes the
/// inspector grow past the window. A scroll view keeps the header and path in place.
final class CertificateScrollView: NSScrollView {
    let certificateView = SFCertificateView()
    var configuredChain: [Data] = []
    var configuredNetworkFetch = false
    /// Keeps the trust object alive after it is handed to the certificate panel.
    var displayedTrust: SecTrust?
    private var resizing = false
    private var measuredWidth: CGFloat = 0
    private var measuredHeight: CGFloat = 0

    func invalidateMeasurement() {
        measuredWidth = 0
        measuredHeight = 0
    }

    override var intrinsicContentSize: NSSize {
        NSSize(width: NSView.noIntrinsicMetric, height: NSView.noIntrinsicMetric)
    }

    override init(frame frameRect: NSRect) {
        super.init(frame: frameRect)
        hasVerticalScroller = true
        autohidesScrollers = false
        drawsBackground = false
        borderType = .noBorder
        clipsToBounds = true
        contentView.clipsToBounds = true
        documentView = certificateView
        setContentCompressionResistancePriority(.defaultLow, for: .vertical)
        setContentHuggingPriority(.defaultLow, for: .vertical)
    }

    required init?(coder: NSCoder) {
        nil
    }

    override func layout() {
        super.layout()
        resizeDocument()
    }

    override func setFrameSize(_ newSize: NSSize) {
        super.setFrameSize(newSize)
        resizeDocument()
    }

    private func resizeDocument() {
        guard !resizing else { return }
        let width = contentSize.width > 1 ? contentSize.width : bounds.width
        guard width > 1 else { return }
        if abs(width - measuredWidth) < 0.5, abs(certificateView.frame.height - measuredHeight) < 0.5 {
            return
        }
        resizing = true
        defer { resizing = false }
        // fittingSize echoes the current frame, so the document is given a tall
        // fixed height and the scroll view reveals the rest.
        let height: CGFloat = 2200
        measuredWidth = width
        measuredHeight = height
        certificateView.frame = NSRect(x: 0, y: 0, width: width, height: height)
    }
}
