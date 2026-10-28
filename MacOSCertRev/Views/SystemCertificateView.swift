import Security
import SecurityInterface
import SwiftUI

struct SystemCertificateView: NSViewRepresentable {
    let certificate: SecCertificate

    func makeNSView(context: Context) -> CertificateScrollView {
        let scroll = CertificateScrollView()
        configure(scroll.certificateView)
        return scroll
    }

    func updateNSView(_ scroll: CertificateScrollView, context: Context) {
        if let current = scroll.certificateView.certificate()?.takeUnretainedValue(),
           CFEqual(current, certificate) {
            return
        }
        configure(scroll.certificateView)
        scroll.invalidateMeasurement()
        scroll.layoutSubtreeIfNeeded()
    }

    private func configure(_ view: SFCertificateView) {
        view.setCertificate(certificate)
        view.setPolicies(SecPolicyCreateBasicX509())
        view.setDisplayDetails(true)
        view.setDetailsDisclosed(true)
        view.setDisplayTrust(true)
        // Trust editing writes the user's trust settings. This app only inspects.
        view.setEditableTrust(false)
    }
}

/// `SFCertificateView` reports a tall fitting size. Hosting it directly makes the
/// inspector grow past the window. A scroll view keeps the header and path in place.
final class CertificateScrollView: NSScrollView {
    let certificateView = SFCertificateView()
    private var resizing = false
    private var measuredWidth: CGFloat = 0
    private var measuredHeight: CGFloat = 0

    func invalidateMeasurement() {
        measuredWidth = 0
        measuredHeight = 0
    }

    override init(frame frameRect: NSRect) {
        super.init(frame: frameRect)
        hasVerticalScroller = true
        autohidesScrollers = false
        drawsBackground = false
        borderType = .noBorder
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
