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

    struct Hierarchy {
        var root: Data
        var intermediate: Data
        var leaf: Data
    }

    /// A leaf signed by an intermediate, signed by a root. The root is not an intermediate.
    static func hierarchy() throws -> Hierarchy {
        let rootKey = Certificate.PrivateKey(P256.Signing.PrivateKey())
        let intermediateKey = Certificate.PrivateKey(P256.Signing.PrivateKey())
        let leafKey = Certificate.PrivateKey(P256.Signing.PrivateKey())
        let rootName = try distinguishedName("CertRev Trust Root")
        let intermediateName = try distinguishedName("CertRev Trust Intermediate")
        let leafName = try distinguishedName("CertRev Trust Leaf")
        let rootSKI = SubjectKeyIdentifier(hash: rootKey.publicKey)
        let intermediateSKI = SubjectKeyIdentifier(hash: intermediateKey.publicKey)

        let root = try issue(
            subject: rootName,
            issuer: rootName,
            serial: 0x21,
            publicKey: rootKey.publicKey,
            signer: rootKey,
            extensions: try Certificate.Extensions {
                Critical(BasicConstraints.isCertificateAuthority(maxPathLength: nil))
                Critical(KeyUsage(digitalSignature: true, keyCertSign: true))
                rootSKI
            }
        )
        let intermediate = try issue(
            subject: intermediateName,
            issuer: rootName,
            serial: 0x22,
            publicKey: intermediateKey.publicKey,
            signer: rootKey,
            extensions: try Certificate.Extensions {
                Critical(BasicConstraints.isCertificateAuthority(maxPathLength: 0))
                Critical(KeyUsage(digitalSignature: true, keyCertSign: true))
                intermediateSKI
                AuthorityKeyIdentifier(keyIdentifier: rootSKI.keyIdentifier)
            }
        )
        let leaf = try issue(
            subject: leafName,
            issuer: intermediateName,
            serial: 0x23,
            publicKey: leafKey.publicKey,
            signer: intermediateKey,
            extensions: try Certificate.Extensions {
                Critical(BasicConstraints.notCertificateAuthority)
                Critical(KeyUsage(digitalSignature: true))
                AuthorityKeyIdentifier(keyIdentifier: intermediateSKI.keyIdentifier)
            }
        )
        return Hierarchy(root: root, intermediate: intermediate, leaf: leaf)
    }

    private static func distinguishedName(_ commonName: String) throws -> DistinguishedName {
        try DistinguishedName {
            CountryName("US")
            OrganizationName("CertRev")
            CommonName(commonName)
        }
    }

    private static func issue(
        subject: DistinguishedName,
        issuer: DistinguishedName,
        serial: UInt8,
        publicKey: Certificate.PublicKey,
        signer: Certificate.PrivateKey,
        extensions: Certificate.Extensions
    ) throws -> Data {
        let now = Date()
        let certificate = try Certificate(
            version: .v3,
            serialNumber: Certificate.SerialNumber(bytes: [serial, 0x02, 0x03, 0x04]),
            publicKey: publicKey,
            notValidBefore: now.addingTimeInterval(-3_600),
            notValidAfter: now.addingTimeInterval(86_400 * 30),
            issuer: issuer,
            subject: subject,
            signatureAlgorithm: .ecdsaWithSHA256,
            extensions: extensions,
            issuerPrivateKey: signer
        )
        var serializer = DER.Serializer()
        try serializer.serialize(certificate)
        return Data(serializer.serializedBytes)
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
