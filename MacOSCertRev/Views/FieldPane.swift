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
            .frame(minWidth: 240, idealWidth: 320, maxWidth: 420)
            .frame(maxHeight: .infinity)

            valuePane
                .frame(minWidth: 280, maxWidth: .infinity, maxHeight: .infinity)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
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
