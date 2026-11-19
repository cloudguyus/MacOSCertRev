import SwiftUI

struct FieldPane: View {
    @Bindable var model: InspectorModel

    private var sections: [FieldSection] {
        model.selectedCertificate?.sections ?? []
    }

    var body: some View {
        HSplitView {
            List(selection: $model.selectedFieldID) {
                ForEach(sections) { section in
                    Section(section.title) {
                        ForEach(section.rows) { row in
                            VStack(alignment: .leading, spacing: 2) {
                                Text(row.title)
                                if let subtitle = row.subtitle {
                                    Text(subtitle)
                                        .font(.caption)
                                        .foregroundStyle(.secondary)
                                        .lineLimit(1)
                                }
                            }
                            .tag(row.id)
                            .padding(.vertical, 2)
                        }
                    }
                }
            }
            .frame(minWidth: 200, idealWidth: 260, maxWidth: 420)
            .frame(maxHeight: .infinity)
            .background(RawFieldSplitClamp())

            valuePane
                .frame(minWidth: 200, maxWidth: .infinity, maxHeight: .infinity)
                .layoutPriority(1)
        }
        .frame(minWidth: 400, maxWidth: .infinity, maxHeight: .infinity)
    }

    @ViewBuilder
    private var valuePane: some View {
        if let row = model.selectedField {
            VStack(alignment: .leading, spacing: 8) {
                Text(row.title)
                    .font(.headline)
                if let subtitle = row.subtitle {
                    Text(subtitle)
                        .font(.caption)
                        .foregroundStyle(.secondary)
                        .textSelection(.enabled)
                }
                ScrollView {
                    Text(row.value)
                        .font(.system(.body, design: .monospaced))
                        .textSelection(.enabled)
                        .frame(maxWidth: .infinity, alignment: .leading)
                }
            }
            .padding(16)
            .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
        } else {
            ContentUnavailableView("No Field", systemImage: "list.bullet.rectangle", description: Text("Select a field to see its value."))
        }
    }
}

/// The field list's SwiftUI minimum is not the split view's divider position.
/// This keeps that divider at a readable width, remembers a drag, and clamps it.
private struct RawFieldSplitClamp: NSViewRepresentable {
    func makeNSView(context: Context) -> RawFieldSplitClampView {
        RawFieldSplitClampView(frame: .zero)
    }

    func updateNSView(_ view: RawFieldSplitClampView, context: Context) {
        view.apply()
    }
}

private final class RawFieldSplitClampView: NSView {
    private let autosaveName = "CertRevRawFieldSplit"
    private let minListWidth: CGFloat = 200
    private let idealListWidth: CGFloat = 260
    private let maxListWidth: CGFloat = 420
    private let minValueWidth: CGFloat = 200
    private var applying = false

    override func viewDidMoveToWindow() {
        super.viewDidMoveToWindow()
        apply()
    }

    override func layout() {
        super.layout()
        apply()
    }

    func apply() {
        guard !applying, let split = enclosingSplit(), split.subviews.count > 1 else { return }
        guard let listPane = split.subviews.first, isDescendant(of: listPane) else { return }
        let total = split.bounds.width
        guard total > 1 else { return }
        applying = true
        defer { applying = false }
        if split.autosaveName != autosaveName {
            split.autosaveName = autosaveName
        }
        split.setHoldingPriority(.defaultHigh, forSubviewAt: 0)
        split.setHoldingPriority(.defaultLow, forSubviewAt: 1)
        let current = listPane.frame.width
        let maxAllowed = min(maxListWidth, max(minListWidth, total - minValueWidth))
        let minAllowed = min(minListWidth, maxAllowed)
        if current + 0.5 < minAllowed {
            let target = min(max(idealListWidth, minAllowed), maxAllowed)
            split.setPosition(target, ofDividerAt: 0)
        } else if current > maxAllowed + 0.5 {
            split.setPosition(maxAllowed, ofDividerAt: 0)
        }
    }

    private func enclosingSplit() -> NSSplitView? {
        var view: NSView? = self
        while let current = view {
            if let split = current as? NSSplitView { return split }
            view = current.superview
        }
        return nil
    }
}
