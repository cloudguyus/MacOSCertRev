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

    private func configure(_ scroll: CertificateScrollView) {
        guard let certificate = SecCertificateCreateWithData(nil, der as CFData) else { return }
        let view = scroll.certificateView
        view.setPolicies(SecPolicyCreateBasicX509())
        view.setCertificate(certificate)
        view.setDisplayDetails(true)
        view.setDetailsDisclosed(true)
        // Trust editing writes the user's trust settings. This app only inspects.
        view.setEditableTrust(false)
        hideTrustLine(view)
        scroll.configuredDER = der
    }

    /// The panel evaluates the one certificate it was given, so its trust sentence
    /// can disagree with the badge. There is no public API to pass the rest of the
    /// bundle. `setDisplayTrust(false)` is the documented way to hide that sentence.
    /// `setCertificate` can turn it back on once the view is in a window, so layout
    /// applies the flag again.
    static func hideTrustLine(_ view: SFCertificateView) {
        view.setDisplayTrust(false)
    }
}

/// `SFCertificateView` reports a tall fitting size. Hosting it directly makes the
/// inspector grow past the window. A scroll view keeps the header and path in place.
final class CertificateScrollView: NSScrollView {
    let certificateView = SFCertificateView()
    var configuredDER: Data?
    private var resizing = false
    private var revealTopOnNextResize = true
    private var measuredWidth: CGFloat = 0
    private var measuredHeight: CGFloat = 0

    func invalidateMeasurement() {
        measuredWidth = 0
        measuredHeight = 0
        revealTopOnNextResize = true
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
        SystemCertificateView.hideTrustLine(certificateView)
        resizeDocument()
    }

    override func viewDidMoveToWindow() {
        super.viewDidMoveToWindow()
        SystemCertificateView.hideTrustLine(certificateView)
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
            revealTopIfNeeded()
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
        revealTopIfNeeded()
    }

    private func revealTopIfNeeded() {
        guard revealTopOnNextResize, contentView.bounds.height > 1 else { return }
        revealTop()
        revealTopOnNextResize = false
    }

    /// A tall document in this scroll view otherwise opens on its bottom edge,
    /// which is the fingerprints section of the certificate panel.
    private func revealTop() {
        guard let document = documentView else { return }
        let clipHeight = contentView.bounds.height
        let y = document.isFlipped ? 0 : max(0, document.frame.height - clipHeight)
        contentView.scroll(to: NSPoint(x: 0, y: y))
        reflectScrolledClipView(contentView)
    }
}
