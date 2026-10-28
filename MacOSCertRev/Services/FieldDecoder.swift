import Foundation
import SwiftASN1
import X509

enum FieldDecoder {
    static func decode(der: Data, index: Int) throws -> ParsedCertificate {
        let certificate: Certificate
        do {
            certificate = try Certificate(derEncoded: Array(der))
        } catch {
            throw CertificateLoadError.notACertificate(fileName: "certificate")
        }

        let summary = CertificateSummary(
            commonName: commonName(of: certificate.subject),
            subject: String(describing: certificate.subject),
            issuer: String(describing: certificate.issuer),
            serialHex: HexEncoding.string(from: certificate.serialNumber.bytes, bytesPerLine: 32),
            notBefore: certificate.notValidBefore,
            notAfter: certificate.notValidAfter
        )

        let sections = [
            certificateSection(certificate),
            nameSection(id: "issuer", title: "Issuer", name: certificate.issuer),
            nameSection(id: "subject", title: "Subject", name: certificate.subject),
            validitySection(certificate),
            publicKeySection(certificate),
            extensionsSection(certificate),
            signatureSection(certificate),
            pemSection(der),
        ]

        return ParsedCertificate(id: index, der: der, summary: summary, sections: sections)
    }

    private static func pemSection(_ der: Data) -> FieldSection {
        FieldSection(
            id: "pem",
            title: "PEM",
            rows: [
                FieldRow(
                    id: "pem.block",
                    title: "PEM",
                    value: PEMEncoding.certificate(from: der),
                    subtitle: nil
                ),
            ]
        )
    }

    private static func certificateSection(_ certificate: Certificate) -> FieldSection {
        FieldSection(
            id: "certificate",
            title: "Certificate",
            rows: [
                FieldRow(id: "certificate.version", title: "Version", value: versionText(certificate.version), subtitle: nil),
                FieldRow(
                    id: "certificate.serial",
                    title: "Serial Number",
                    value: HexEncoding.string(from: certificate.serialNumber.bytes, bytesPerLine: 32),
                    subtitle: nil
                ),
                FieldRow(
                    id: "certificate.signatureAlgorithm",
                    title: "Signature Algorithm",
                    value: signatureAlgorithmText(certificate.signatureAlgorithm),
                    subtitle: nil
                ),
            ]
        )
    }

    private static func nameSection(id: String, title: String, name: DistinguishedName) -> FieldSection {
        var rows = [
            FieldRow(id: "\(id).dn", title: "Distinguished Name", value: String(describing: name), subtitle: nil),
        ]
        var index = 0
        for rdn in name {
            for attribute in rdn {
                rows.append(
                    FieldRow(
                        id: "\(id).\(index)",
                        title: attributeTitle(attribute.type),
                        value: String(describing: attribute.value),
                        subtitle: String(describing: attribute.type)
                    )
                )
                index += 1
            }
        }
        return FieldSection(id: id, title: title, rows: rows)
    }

    private static func validitySection(_ certificate: Certificate) -> FieldSection {
        FieldSection(
            id: "validity",
            title: "Validity",
            rows: [
                FieldRow(id: "validity.notBefore", title: "Not Before", value: dateText(certificate.notValidBefore), subtitle: nil),
                FieldRow(id: "validity.notAfter", title: "Not After", value: dateText(certificate.notValidAfter), subtitle: nil),
            ]
        )
    }

    private static func publicKeySection(_ certificate: Certificate) -> FieldSection {
        FieldSection(
            id: "publicKey",
            title: "Public Key",
            rows: [
                FieldRow(id: "publicKey.algorithm", title: "Algorithm", value: publicKeyText(certificate.publicKey), subtitle: nil),
                FieldRow(
                    id: "publicKey.bytes",
                    title: "Subject Public Key",
                    value: HexEncoding.string(from: certificate.publicKey.subjectPublicKeyInfoBytes),
                    subtitle: nil
                ),
            ]
        )
    }

    private static func extensionsSection(_ certificate: Certificate) -> FieldSection {
        let rows = certificate.extensions.enumerated().map { offset, ext in
            FieldRow(
                id: "extension.\(offset)",
                title: extensionTitle(ext),
                value: extensionBody(ext),
                subtitle: "\(ext.critical ? "Critical" : "Not critical") · \(ext.oid)"
            )
        }
        return FieldSection(id: "extensions", title: "Extensions", rows: rows)
    }

    private static func signatureSection(_ certificate: Certificate) -> FieldSection {
        FieldSection(
            id: "signature",
            title: "Signature",
            rows: [
                FieldRow(
                    id: "signature.bytes",
                    title: "Signature Value",
                    value: HexEncoding.string(from: certificate.signature.rawRepresentation),
                    subtitle: signatureAlgorithmText(certificate.signatureAlgorithm)
                ),
            ]
        )
    }

    private static func extensionBody(_ ext: Certificate.Extension) -> String {
        let formatted = formattedExtension(ext) ?? "No typed decoder for this extension."
        let raw = HexEncoding.string(from: ext.value)
        guard !raw.isEmpty else { return formatted }
        return "\(formatted)\n\nRaw value\n\(raw)"
    }

    private static func formattedExtension(_ ext: Certificate.Extension) -> String? {
        switch ext.oid {
        case .X509ExtensionID.subjectAlternativeName:
            guard let names = try? SubjectAlternativeNames(ext) else { return nil }
            return names.map(formatGeneralName).joined(separator: "\n")
        case .X509ExtensionID.keyUsage:
            guard let usage = try? KeyUsage(ext) else { return nil }
            return keyUsageText(usage)
        case .X509ExtensionID.extendedKeyUsage:
            guard let usage = try? ExtendedKeyUsage(ext) else { return nil }
            return usage.map(extendedUsageText).joined(separator: "\n")
        case .X509ExtensionID.basicConstraints:
            guard let constraints = try? BasicConstraints(ext) else { return nil }
            return basicConstraintsText(constraints)
        case .X509ExtensionID.subjectKeyIdentifier:
            guard let identifier = try? SubjectKeyIdentifier(ext) else { return nil }
            return HexEncoding.string(from: identifier.keyIdentifier, bytesPerLine: 32)
        case .X509ExtensionID.authorityKeyIdentifier:
            guard let identifier = try? AuthorityKeyIdentifier(ext) else { return nil }
            return authorityKeyText(identifier)
        case .X509ExtensionID.authorityInformationAccess:
            guard let access = try? AuthorityInformationAccess(ext) else { return nil }
            return access.map { "\($0.method): \(formatGeneralName($0.location))" }.joined(separator: "\n")
        case .X509ExtensionID.nameConstraints:
            guard let constraints = try? NameConstraints(ext) else { return nil }
            return nameConstraintsText(constraints)
        default:
            return nil
        }
    }

    private static func extensionTitle(_ ext: Certificate.Extension) -> String {
        switch ext.oid {
        case .X509ExtensionID.subjectAlternativeName:
            return "Subject Alternative Name"
        case .X509ExtensionID.keyUsage:
            return "Key Usage"
        case .X509ExtensionID.extendedKeyUsage:
            return "Extended Key Usage"
        case .X509ExtensionID.basicConstraints:
            return "Basic Constraints"
        case .X509ExtensionID.subjectKeyIdentifier:
            return "Subject Key Identifier"
        case .X509ExtensionID.authorityKeyIdentifier:
            return "Authority Key Identifier"
        case .X509ExtensionID.authorityInformationAccess:
            return "Authority Information Access"
        case .X509ExtensionID.nameConstraints:
            return "Name Constraints"
        default:
            return String(describing: ext.oid)
        }
    }

    private static func formatGeneralName(_ name: GeneralName) -> String {
        switch name {
        case .dnsName(let value):
            return "DNS: \(value)"
        case .rfc822Name(let value):
            return "Email: \(value)"
        case .uniformResourceIdentifier(let value):
            return "URI: \(value)"
        case .ipAddress(let address):
            return "IP: \(HexEncoding.internetAddress(address.bytes))"
        case .directoryName(let directory):
            return "Directory: \(directory)"
        case .registeredID(let identifier):
            return "Registered ID: \(identifier)"
        case .otherName(let other):
            return "Other: \(other)"
        case .x400Address:
            return "X.400 address"
        case .ediPartyName:
            return "EDI party name"
        }
    }

    private static func keyUsageText(_ usage: KeyUsage) -> String {
        let names: [(Bool, String)] = [
            (usage.digitalSignature, "Digital Signature"),
            (usage.nonRepudiation, "Non-Repudiation"),
            (usage.keyEncipherment, "Key Encipherment"),
            (usage.dataEncipherment, "Data Encipherment"),
            (usage.keyAgreement, "Key Agreement"),
            (usage.keyCertSign, "Certificate Sign"),
            (usage.cRLSign, "CRL Sign"),
            (usage.encipherOnly, "Encipher Only"),
            (usage.decipherOnly, "Decipher Only"),
        ]
        let enabled = names.compactMap { enabled, name in enabled ? name : nil }
        return enabled.isEmpty ? "No usages set" : enabled.joined(separator: "\n")
    }

    private static func extendedUsageText(_ usage: ExtendedKeyUsage.Usage) -> String {
        switch usage {
        case .serverAuth:
            return "Server Authentication"
        case .clientAuth:
            return "Client Authentication"
        case .codeSigning:
            return "Code Signing"
        case .emailProtection:
            return "Email Protection"
        case .timeStamping:
            return "Time Stamping"
        case .ocspSigning:
            return "OCSP Signing"
        case .any:
            return "Any"
        case .certificateTransparency:
            return "Certificate Transparency"
        default:
            return String(describing: usage)
        }
    }

    private static func basicConstraintsText(_ constraints: BasicConstraints) -> String {
        switch constraints {
        case .isCertificateAuthority(let maxPathLength):
            if let maxPathLength {
                return "Certificate Authority\nMaximum path length: \(maxPathLength)"
            }
            return "Certificate Authority"
        case .notCertificateAuthority:
            return "Not a certificate authority"
        }
    }

    private static func authorityKeyText(_ identifier: AuthorityKeyIdentifier) -> String {
        var lines: [String] = []
        if let keyIdentifier = identifier.keyIdentifier {
            lines.append("Key ID: \(HexEncoding.string(from: keyIdentifier, bytesPerLine: 32))")
        }
        if let issuer = identifier.authorityCertIssuer {
            lines.append("Issuer: \(issuer.map(formatGeneralName).joined(separator: ", "))")
        }
        if let serial = identifier.authorityCertSerialNumber {
            lines.append("Serial: \(HexEncoding.string(from: serial.bytes, bytesPerLine: 32))")
        }
        return lines.isEmpty ? "Empty" : lines.joined(separator: "\n")
    }

    private static func nameConstraintsText(_ constraints: NameConstraints) -> String {
        var lines: [String] = []
        if !constraints.permittedSubtrees.isEmpty {
            lines.append("Permitted")
            lines.append(contentsOf: constraints.permittedSubtrees.map { "  \(formatGeneralName($0))" })
        }
        if !constraints.excludedSubtrees.isEmpty {
            lines.append("Excluded")
            lines.append(contentsOf: constraints.excludedSubtrees.map { "  \(formatGeneralName($0))" })
        }
        return lines.isEmpty ? "No name constraints" : lines.joined(separator: "\n")
    }

    private static func attributeTitle(_ type: ASN1ObjectIdentifier) -> String {
        switch type {
        case .RDNAttributeType.commonName:
            return "Common Name"
        case .RDNAttributeType.countryName:
            return "Country"
        case .RDNAttributeType.localityName:
            return "Locality"
        case .RDNAttributeType.stateOrProvinceName:
            return "State or Province"
        case .RDNAttributeType.organizationName:
            return "Organization"
        case .RDNAttributeType.organizationalUnitName:
            return "Organizational Unit"
        default:
            return String(describing: type)
        }
    }

    private static func commonName(of name: DistinguishedName) -> String {
        for rdn in name {
            for attribute in rdn where attribute.type == .RDNAttributeType.commonName {
                let value = String(describing: attribute.value)
                if !value.isEmpty { return value }
            }
        }
        let text = String(describing: name)
        return text.isEmpty ? "Certificate" : text
    }

    private static func versionText(_ version: Certificate.Version) -> String {
        if version == .v1 { return "1" }
        if version == .v3 { return "3" }
        let description = version.description
        if description.hasPrefix("X509v") {
            return String(description.dropFirst(5))
        }
        return description
    }

    private static func signatureAlgorithmText(_ algorithm: Certificate.SignatureAlgorithm) -> String {
        switch algorithm {
        case .ecdsaWithSHA256:
            return "ECDSA with SHA-256"
        case .ecdsaWithSHA384:
            return "ECDSA with SHA-384"
        case .ecdsaWithSHA512:
            return "ECDSA with SHA-512"
        case .sha1WithRSAEncryption:
            return "RSA with SHA-1"
        case .sha256WithRSAEncryption:
            return "RSA with SHA-256"
        case .sha384WithRSAEncryption:
            return "RSA with SHA-384"
        case .sha512WithRSAEncryption:
            return "RSA with SHA-512"
        case .ed25519:
            return "Ed25519"
        default:
            return String(describing: algorithm)
        }
    }

    private static func publicKeyText(_ key: Certificate.PublicKey) -> String {
        switch key.description {
        case "P256.PublicKey":
            return "ECDSA P-256"
        case "P384.PublicKey":
            return "ECDSA P-384"
        case "P521.PublicKey":
            return "ECDSA P-521"
        case "Ed25519.PublicKey":
            return "Ed25519"
        default:
            if key.description.hasPrefix("RSA") {
                let digits = key.description.dropFirst(3).prefix(while: \.isNumber)
                if !digits.isEmpty { return "RSA \(digits)" }
            }
            return key.description
        }
    }

    private static func dateText(_ date: Date) -> String {
        let local = date.formatted(date: .long, time: .standard)
        let utc = date.formatted(
            Date.ISO8601FormatStyle(
                includingFractionalSeconds: false,
                timeZone: TimeZone(secondsFromGMT: 0) ?? .gmt
            )
        )
        return "Local: \(local)\nUTC: \(utc)"
    }
}
