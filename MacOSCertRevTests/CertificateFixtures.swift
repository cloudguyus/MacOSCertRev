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
