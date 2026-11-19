import SwiftUI

struct FieldPane: View {
    @Bindable var model: InspectorModel

    private var sections: [FieldSection] {
        model.selectedCertificate?.sections ?? []
    }

    var body: some View {
        GeometryReader { proxy in
            let listWidth = fieldListWidth(available: proxy.size.width)
            HStack(spacing: 0) {
                fieldList
                    .frame(width: listWidth, height: proxy.size.height)
                Divider()
                valuePane
                    .frame(minWidth: 0, maxWidth: .infinity, maxHeight: .infinity)
                    .frame(height: proxy.size.height)
            }
            .frame(width: proxy.size.width, height: proxy.size.height, alignment: .leading)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }

    /// 260 points when the detail pane has room for the value beside it.
    /// The width is explicit, so the list cannot collapse to a sliver.
    private func fieldListWidth(available: CGFloat) -> CGFloat {
        let minimum: CGFloat = 200
        let ideal: CGFloat = 260
        let maximum: CGFloat = 420
        let valueMinimum: CGFloat = 200
        guard available > 1 else { return ideal }
        let upper = min(maximum, max(minimum, available - valueMinimum))
        return min(ideal, upper)
    }

    private var fieldList: some View {
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
