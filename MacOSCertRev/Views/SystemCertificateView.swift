import Security
import SecurityInterface
import SwiftUI

struct SystemCertificateView: NSViewRepresentable {
    var der: Data

    func makeNSView(context: Context) -> CertificateScrollView {
        let scroll = CertificateScrollView()
        configure(scroll)
        return scroll
    }

    func updateNSView(_ scroll: CertificateScrollView, context: Context) {
        guard scroll.configuredDER != der else { return }
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
        guard let certificate = SecCertificateCreateWithData(nil, der as CFData) else { return }
        let view = scroll.certificateView
        view.setPolicies(SecPolicyCreateBasicX509())
        view.setCertificate(certificate)
        view.setDisplayDetails(true)
        view.setDetailsDisclosed(true)
        // SFCertificateView's public API is setCertificate(_:) plus policies and
        // display flags. It evaluates trust for that one certificate. There is no
        // public method that accepts a SecTrust or the other certificates in a
        // bundle. SFCertificateTrustPanel and SFCertificatePanel do take a trust
        // or a certificate list, but they are sheets, not this embedded panel.
        // Hiding the panel's trust line leaves the badge and Certification Path,
        // which share one evaluation, as the only trust indicators.
        view.setDisplayTrust(false)
        // Trust editing writes the user's trust settings. This app only inspects.
        view.setEditableTrust(false)
        scroll.configuredDER = der
    }
}

/// `SFCertificateView` reports a tall fitting size. Hosting it directly makes the
/// inspector grow past the window. A scroll view keeps the header and path in place.
final class CertificateScrollView: NSScrollView {
    let certificateView = SFCertificateView()
    var configuredDER: Data?
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
