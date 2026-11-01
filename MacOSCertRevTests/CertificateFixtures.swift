import CryptoKit
import Foundation
import SwiftASN1
import X509

enum CertificateFixtures {
    static func leaf(commonName: String = "leaf.example", serial: UInt8 = 1) throws -> Data {
        try make(
            commonName: commonName,
            serial: serial,
            extensions: try Certificate.Extensions {
                Critical(BasicConstraints.notCertificateAuthority)
                Critical(KeyUsage(digitalSignature: true))
                SubjectAlternativeNames([.dnsName("example.com")])
            }
        )
    }

    static func authority(commonName: String = "ca.example", serial: UInt8 = 2) throws -> Data {
        try make(
            commonName: commonName,
            serial: serial,
            extensions: try Certificate.Extensions {
                Critical(BasicConstraints.isCertificateAuthority(maxPathLength: nil))
                Critical(KeyUsage(digitalSignature: true, keyCertSign: true))
            }
        )
    }

    static func pem(_ der: Data) -> String {
        let body = der.base64EncodedString(options: [.lineLength64Characters, .endLineWithLineFeed])
        return "-----BEGIN CERTIFICATE-----\n\(body)\n-----END CERTIFICATE-----\n"
    }

    /// `X509_CERT_AUX` for a single serverAuth trust OID, as written by
    /// `openssl x509 -trustout -addtrust serverAuth`.
    static let serverAuthTrustAux = Data([
        0x30, 0x0C, 0x30, 0x0A, 0x06, 0x08, 0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x01,
    ])

    /// OpenSSL trusted-certificate PEM. `aux` is appended after the certificate DER.
    static func trustedPEM(_ der: Data, aux: Data = Data()) -> String {
        var body = der
        body.append(aux)
        return trustedPEM(body: body)
    }

    /// Trusted-certificate PEM whose decoded body is `body` exactly.
    static func trustedPEM(body: Data) -> String {
        let encoded = body.base64EncodedString(options: [.lineLength64Characters, .endLineWithLineFeed])
        return "-----BEGIN TRUSTED CERTIFICATE-----\n\(encoded)\n-----END TRUSTED CERTIFICATE-----\n"
    }

    private static func make(commonName: String, serial: UInt8, extensions: Certificate.Extensions) throws -> Data {
        let privateKey = Certificate.PrivateKey(P256.Signing.PrivateKey())
        let name = try DistinguishedName {
            CountryName("US")
            OrganizationName("CertRev")
            CommonName(commonName)
        }
        let now = Date()
        let certificate = try Certificate(
            version: .v3,
            serialNumber: Certificate.SerialNumber(bytes: [serial, 0x02, 0x03, 0x04]),
            publicKey: privateKey.publicKey,
            notValidBefore: now.addingTimeInterval(-3_600),
            notValidAfter: now.addingTimeInterval(86_400 * 30),
            issuer: name,
            subject: name,
            signatureAlgorithm: .ecdsaWithSHA256,
            extensions: extensions,
            issuerPrivateKey: privateKey
        )
        var serializer = DER.Serializer()
        try serializer.serialize(certificate)
        return Data(serializer.serializedBytes)
    }
}
