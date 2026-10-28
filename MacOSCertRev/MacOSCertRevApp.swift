import AppKit
import SwiftUI

@main
struct MacOSCertRevApp: App {
    @NSApplicationDelegateAdaptor(AppDelegate.self) private var appDelegate
    @State private var model = InspectorModel.shared

    var body: some Scene {
        WindowGroup {
            ContentView(model: model)
                .background(WindowMinimumSize(size: NSSize(width: 980, height: 740)))
        }
        .defaultSize(width: 1080, height: 760)
        .commands {
            CommandGroup(replacing: .newItem) {
                Button("Open…") {
                    InspectorModel.shared.openPanel()
                }
                .keyboardShortcut("o")
            }
        }
    }
}

/// SwiftUI's min frame does not raise `NSWindow.minSize`, so a restored short
/// window clips the inspector. This sets the window minimum and grows a window
/// that was saved smaller than that.
private struct WindowMinimumSize: NSViewRepresentable {
    var size: NSSize

    func makeNSView(context: Context) -> WindowMinimumSizeView {
        let view = WindowMinimumSizeView(frame: .zero)
        view.minimumSize = size
        return view
    }

    func updateNSView(_ view: WindowMinimumSizeView, context: Context) {
        view.minimumSize = size
    }
}

private final class WindowMinimumSizeView: NSView {
    var minimumSize: NSSize = .zero {
        didSet {
            guard oldValue != minimumSize else { return }
            applyMinimumSize()
        }
    }

    private var applying = false

    override func viewDidMoveToWindow() {
        super.viewDidMoveToWindow()
        applyMinimumSize()
    }

    private func applyMinimumSize() {
        guard !applying, let window, minimumSize.width > 0, minimumSize.height > 0 else { return }
        applying = true
        defer { applying = false }
        // Set the minimum once. Resizing in response to didResize fights SwiftUI
        // and can pin the main thread.
        if window.minSize != minimumSize {
            window.minSize = minimumSize
        }
        let frame = window.frame
        guard frame.width + 0.5 < minimumSize.width || frame.height + 0.5 < minimumSize.height else { return }
        let width = max(frame.width, minimumSize.width)
        let height = max(frame.height, minimumSize.height)
        window.setFrame(
            NSRect(
                x: frame.origin.x,
                y: frame.origin.y - (height - frame.height),
                width: width,
                height: height
            ),
            display: true
        )
    }
}

@MainActor
final class AppDelegate: NSObject, NSApplicationDelegate {
    func application(_ application: NSApplication, open urls: [URL]) {
        guard let url = urls.first else { return }
        InspectorModel.shared.load(url: url)
    }
}
