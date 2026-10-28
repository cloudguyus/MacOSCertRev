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

    private static func evaluateBlocking(
        ders: [Data],
        leafIndex: Int,
        options: TrustEvaluationOptions
    ) -> TrustReport {
        guard ders.indices.contains(leafIndex) else {
            return TrustReport(succeeded: false, message: "No certificate is selected.", chain: [])
        }

        var ordered = [ders[leafIndex]]
        for (index, der) in ders.enumerated() where index != leafIndex {
            ordered.append(der)
        }

        let certificates = ordered.compactMap { SecCertificateCreateWithData(nil, $0 as CFData) }
        guard certificates.count == ordered.count else {
            return TrustReport(
                succeeded: false,
                message: "The certificate could not be prepared for trust evaluation.",
                chain: []
            )
        }

        var trust: SecTrust?
        let status = SecTrustCreateWithCertificates(certificates as CFArray, SecPolicyCreateBasicX509(), &trust)
        guard status == errSecSuccess, let trust else {
            return TrustReport(succeeded: false, message: "Trust evaluation could not start.", chain: [])
        }

        // Network fetch stays off unless the toolbar toggle is on. This object is never stored.
        SecTrustSetNetworkFetchAllowed(trust, options.networkFetchAllowed)
        if let anchorDERs = options.anchorDERs {
            let anchors = anchorDERs.compactMap { SecCertificateCreateWithData(nil, $0 as CFData) }
            SecTrustSetAnchorCertificates(trust, anchors as CFArray)
            SecTrustSetAnchorCertificatesOnly(trust, true)
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
