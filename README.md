# CertRev

CertRev is a Mac app for reading an X.509 certificate. Open a `.cer`, `.crt`, `.der`, `.pem`, PKCS#12 (`.p12`, `.pfx`), or PKCS#7 (`.p7b`, `.p7c`) file and review the certificate without importing it into Keychain and without OpenSSL.

The official build is the one published from [github.com/cloudguyus/MacOSCertRev](https://github.com/cloudguyus/MacOSCertRev).

## What you can do

- Drop a certificate on the window, or use Open. macOS can also open a certificate file with CertRev.
- PKCS#12 (`.p12`, `.pfx`) opens after a password prompt. Leave the password blank when the file has none. An OpenSSL 3 export with a blank password is the exception under What it refuses. Every certificate in the bundle is listed, leaf first. When a private key is present, CertRev shows its type and size only. The password and the key bytes are discarded after import and are not added to Keychain. A Keychain export that uses RC2 or 3DES opens when this version of macOS can decrypt it.
- PKCS#7 (`.p7b`, `.p7c`) opens a certs-only bundle in DER or PEM (`-----BEGIN PKCS7-----`). Certificates are ordered leaf to root when they chain, and a certificate that does not chain is marked.
- The header shows the subject, issuer, serial number, and the not-before and not-after dates, with a trust badge beside the name.
- **System view** is the default. It is the macOS certificate panel for the selected certificate. That panel only sees the selected certificate, without its chain, so CertRev hides the panel's own trust line. The trust badge and Certification Path show the chain trust result. Trust settings in that panel cannot be edited.
- **View Text** shows the selected certificate as `-----BEGIN CERTIFICATE-----` … `-----END CERTIFICATE-----` text. You can select it.
- **Copy Certificate** copies that same text. The toolbar Copy command does this too, unless RAW is on.
- **RAW** lists each field and its value. The field list is a fixed-width column, and the value uses the rest of the pane. Copy then copies the selected field.
- A file with more than one certificate lists them in a sidebar. The window title is the file name. The selected certificate is the one on screen. Trust evaluation treats that certificate as the leaf and includes the others from the file.
- **Certification Path** shows the chain macOS built and the evaluation result.
- **Fetch intermediates** stays off unless you turn it on. Off, trust uses the certificates in the file and the local trust store. On, that trust check may download a missing intermediate. It does not import anything into Keychain, and it cannot make an expired or untrusted certificate trusted.

## What it refuses

- A PEM file that contains a private key. The key bytes are not shown.
- A PKCS#7 file that is signed or enveloped data, rather than a certificate bundle.
- Certificate revocation lists. Those are not supported yet.
- A `.p12` exported by OpenSSL 3 with a blank password. OpenSSL 3 writes the MAC differently from macOS, so macOS cannot open it. CertRev says: This PKCS#12 file uses a blank-password encoding that this version of macOS cannot import. Export it again and set a password. It does not call the file corrupt or the password wrong.
- A PKCS#12 file whose encryption is legacy RC2 or 3DES, when this version of macOS cannot decrypt it. CertRev says: This PKCS#12 file uses legacy RC2 or 3DES encryption, which this version of macOS cannot open. Export it again with AES-256. The password is not reported as wrong when the cipher is the problem.

CertRev keeps the certificate in memory. It does not add it to a keychain.

How to regenerate the test bundles and check them on a Mac is in [docs/TESTING-PKCS.md](docs/TESTING-PKCS.md).

## Requirements

macOS 15 or later. The published app is a universal binary for Apple silicon (arm64) and Intel (x86_64).

## Install with Homebrew

```
brew install --cask cloudguyus/tap/certrev
```

Upgrade with:

```
brew upgrade --cask cloudguyus/tap/certrev
```

This is a public tap under the cloudguyus account. It is not the untapped `brew install --cask certrev` catalog.

## Install from a download

Download `CertRev-<version>.zip` from the [releases](https://github.com/cloudguyus/MacOSCertRev/releases) page, unzip it, and move `CertRev.app` to Applications.

This build is ad-hoc signed. macOS has not notarized it, because the publisher does not yet have an Apple Developer ID. The first open of a downloaded copy can say the developer cannot be verified. Right-click CertRev and choose Open. The Homebrew install clears that download flag when it can.

A later release can replace this build with one signed by a Developer ID. The install command stays the same. `brew upgrade --cask cloudguyus/tap/certrev` moves an existing install onto that signed build.

## Privacy

The certificate stays in memory for the session. The network is used only while Fetch intermediates is on, and only for that trust check.

## License

MIT. Copyright (c) 2026 cloudguyus. Copies of this code keep that copyright notice. See [LICENSE](LICENSE).

## Publishing a version

Bump `MARKETING_VERSION` in the Xcode project so it matches the tag, commit, and push a tag such as `v1.0.1`. The release workflow builds a universal app (arm64 and x86_64), publishes `CertRev-1.0.1.zip` on GitHub, and updates the Homebrew tap checksum.
