import Foundation

enum HexEncoding {
    static func string(from bytes: some Sequence<UInt8>, bytesPerLine: Int = 16) -> String {
        let array = Array(bytes)
        guard !array.isEmpty else { return "" }
        var lines: [String] = []
        var index = 0
        while index < array.count {
            let end = min(index + bytesPerLine, array.count)
            let line = array[index..<end].map { String(format: "%02X", $0) }.joined(separator: " ")
            lines.append(line)
            index = end
        }
        return lines.joined(separator: "\n")
    }

    static func internetAddress(_ bytes: some Sequence<UInt8>) -> String {
        let array = Array(bytes)
        switch array.count {
        case 4:
            return array.map(String.init).joined(separator: ".")
        case 8:
            return "\(internetAddress(array.prefix(4)))–\(internetAddress(array.suffix(4)))"
        case 16:
            return stride(from: 0, to: 16, by: 2).map { index in
                String(format: "%02x%02x", array[index], array[index + 1])
            }.joined(separator: ":")
        case 32:
            return "\(internetAddress(array.prefix(16)))–\(internetAddress(array.suffix(16)))"
        default:
            return string(from: array, bytesPerLine: max(array.count, 1))
        }
    }
}
