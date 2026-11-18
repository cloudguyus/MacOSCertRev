import Foundation
import Security

enum TrustEvaluator {
    static func evaluate(
        ders: [Data],
        leafIndex: Int,
        options: TrustEvaluationOptions
    ) async -> TrustReport {
        let ders = ders
        let leafIndex = leafIndex
        let options = options
        return await Task.detached {
            evaluateBlocking(ders: ders, leafIndex: leafIndex, options: options)
        }.value
    }

    /// Selected certificate first, then the other certificates from the same file.
    /// That order is what `SecTrustCreateWithCertificates` treats as the leaf plus intermediates.
    static func orderedCertificateDERs(_ ders: [Data], leafIndex: Int) -> [Data] {
        guard ders.indices.contains(leafIndex) else { return [] }
        var ordered = [ders[leafIndex]]
        for (index, der) in ders.enumerated() where index != leafIndex {
            ordered.append(der)
        }
        return ordered
    }

    /// The trust object behind the badge. The system certificate panel uses this
    /// same object so the two indicators see the same chain and policy.
    static func makeTrust(
        ders: [Data],
        leafIndex: Int,
        options: TrustEvaluationOptions
    ) -> SecTrust? {
        let ordered = orderedCertificateDERs(ders, leafIndex: leafIndex)
        guard !ordered.isEmpty else { return nil }
        let certificates = ordered.compactMap { SecCertificateCreateWithData(nil, $0 as CFData) }
        guard certificates.count == ordered.count else { return nil }

        var trust: SecTrust?
        let status = SecTrustCreateWithCertificates(certificates as CFArray, SecPolicyCreateBasicX509(), &trust)
        guard status == errSecSuccess, let trust else { return nil }

        // Network fetch stays off unless the toolbar toggle is on.
        SecTrustSetNetworkFetchAllowed(trust, options.networkFetchAllowed)
        if let anchorDERs = options.anchorDERs {
            let anchors = anchorDERs.compactMap { SecCertificateCreateWithData(nil, $0 as CFData) }
            SecTrustSetAnchorCertificates(trust, anchors as CFArray)
            SecTrustSetAnchorCertificatesOnly(trust, true)
        }
        return trust
    }

    private static func evaluateBlocking(
        ders: [Data],
        leafIndex: Int,
        options: TrustEvaluationOptions
    ) -> TrustReport {
        guard ders.indices.contains(leafIndex) else {
            return TrustReport(succeeded: false, message: "No certificate is selected.", chain: [])
        }
        guard let trust = makeTrust(ders: ders, leafIndex: leafIndex, options: options) else {
            return TrustReport(
                succeeded: false,
                message: "The certificate could not be prepared for trust evaluation.",
                chain: []
            )
        }

        var error: CFError?
        let succeeded = SecTrustEvaluateWithError(trust, &error)
        let message: String
        if succeeded {
            message = "Evaluation succeeded."
        } else if let error {
            message = (error as Error).localizedDescription
        } else {
            message = "Evaluation failed."
        }
        return TrustReport(succeeded: succeeded, message: message, chain: chainSummaries(trust))
    }

    private static func chainSummaries(_ trust: SecTrust) -> [String] {
        guard let chain = SecTrustCopyCertificateChain(trust) as? [SecCertificate] else { return [] }
        return chain.map { certificate in
            SecCertificateCopySubjectSummary(certificate) as String? ?? "Certificate"
        }
    }
}
