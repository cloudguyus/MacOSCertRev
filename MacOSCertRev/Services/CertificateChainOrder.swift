import Foundation
import SwiftASN1
import X509

/// Orders certificates leaf to root and marks certificates that do not link to any other.
enum CertificateChainOrder {
    struct Item: Equatable {
        var der: Data
        var unchained: Bool
    }

    static func order(_ ders: [Data]) throws -> [Item] {
        let parsed: [(der: Data, certificate: Certificate)] = try ders.map { der in
            let certificate: Certificate
            do {
                certificate = try Certificate(derEncoded: [UInt8](der))
            } catch {
                throw CertificateLoadError.notACertificate(fileName: "certificate")
            }
            return (der, certificate)
        }

        var parent: [Int: Int] = [:]
        for index in parsed.indices {
            if let issuer = issuerIndex(of: index, in: parsed) {
                parent[index] = issuer
            }
        }
        var children: [Int: [Int]] = [:]
        for (child, issuer) in parent {
            children[issuer, default: []].append(child)
        }

        let leaves = parsed.indices.filter { children[$0] == nil }
        var emitted = Set<Int>()
        var ordered: [Item] = []

        func append(_ index: Int) {
            guard emitted.insert(index).inserted else { return }
            let linked = parent[index] != nil || children[index] != nil
            ordered.append(
                Item(
                    der: parsed[index].der,
                    unchained: parsed.count > 1 && !linked
                )
            )
        }

        for leaf in leaves {
            var index: Int? = leaf
            var steps = 0
            while let current = index, steps <= parsed.count {
                append(current)
                index = parent[current]
                steps += 1
            }
        }
        for index in parsed.indices {
            append(index)
        }
        return ordered
    }

    private static func issuerIndex(
        of index: Int,
        in parsed: [(der: Data, certificate: Certificate)]
    ) -> Int? {
        let certificate = parsed[index].certificate
        let candidates = parsed.indices.filter { candidate in
            candidate != index && parsed[candidate].certificate.subject == certificate.issuer
        }
        if candidates.count <= 1 { return candidates.first }
        if let authority = authorityKeyIdentifier(certificate) {
            if let match = candidates.first(where: { subjectKeyIdentifier(parsed[$0].certificate) == authority }) {
                return match
            }
        }
        return candidates.first
    }

    private static func subjectKeyIdentifier(_ certificate: Certificate) -> [UInt8]? {
        for ext in certificate.extensions where ext.oid == .X509ExtensionID.subjectKeyIdentifier {
            guard let identifier = try? SubjectKeyIdentifier(ext) else { return nil }
            return Array(identifier.keyIdentifier)
        }
        return nil
    }

    private static func authorityKeyIdentifier(_ certificate: Certificate) -> [UInt8]? {
        for ext in certificate.extensions where ext.oid == .X509ExtensionID.authorityKeyIdentifier {
            return try? AuthorityKeyIdentifier(ext).keyIdentifier.map { Array($0) }
        }
        return nil
    }
}
