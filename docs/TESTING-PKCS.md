# Testing PKCS#12 and PKCS#7 import

Manual checks for opening `.p12`, `.pfx`, `.p7b`, and `.p7c` files on a Mac. The fixtures under `MacOSCertRevTests/Fixtures/PKCS/` are throwaway test data, not secrets. Do not replace them with a real key.

## Regenerate the fixtures

From the repository root, with `openssl` on `PATH`:

```
scripts/make-test-fixtures.sh
```

macOS `/usr/bin/openssl` is LibreSSL. Homebrew OpenSSL 3 is also fine. The script detects which one it is. OpenSSL 3 writes the legacy fixture with `-legacy` (RC2 for certificates, 3DES for the private key). LibreSSL still writes that older encryption by default and does not accept `-legacy`.

The PKCS#12 password is `test123`, except the blank-password files. Regenerating replaces the files and needs `python3` as well as `openssl`, because the script rewrites one blank-password MAC. The unit tests read the committed copies, so commit the new files if you regenerate them.

## Run the unit tests

From the repository root:

```
xcodebuild test -project MacOSCertRev.xcodeproj -scheme MacOSCertRev -destination 'platform=macOS'
```

In Xcode, open `MacOSCertRev.xcodeproj`, select the MacOSCertRev scheme, and press Command-U. The PKCS cases are `PKCSBundleTests` and `PKCS12PromptTests`. The rest of the existing suite should pass with them.

## Run the app

In Xcode, select the MacOSCertRev scheme and press Command-R.

From the command line:

```
xcodebuild build -project MacOSCertRev.xcodeproj -scheme MacOSCertRev -destination 'platform=macOS' -derivedDataPath build/DerivedData
open build/DerivedData/Build/Products/Debug/CertRev.app
```

Finder "Open With" uses the app you built. If CertRev is missing from the menu, choose Other…, select that `CertRev.app`, and turn on Always Open With only if you mean to. The document types are registered as alternate handlers, so CertRev should appear without becoming the default.

The fixtures live at:

```
MacOSCertRevTests/Fixtures/PKCS/
```

## What the password sheet does

A PKCS#12 file that is a real PFX opens a sheet. The field is a secure field. Leave it blank and click Open for an empty password. The password is not written to Keychain, not copied, and not kept after the import finishes or the sheet closes. A wrong password stays on the sheet and says:

```
The password is incorrect.
```

The certificate that was already on screen stays there until a password succeeds or you open a different file. Cancel closes the sheet and leaves the previous certificate in place.

These are the other messages:

| Situation | Message |
| --- | --- |
| Corrupt or not a PKCS#12 file | This PKCS#12 file is corrupt or is not a PKCS#12 bundle. |
| Blank password in OpenSSL's split encoding | This PKCS#12 file uses a blank-password encoding that this version of macOS cannot import. Export it again and set a password. |
| Legacy RC2 or 3DES that this macOS cannot decrypt | This PKCS#12 file uses legacy RC2 or 3DES encryption, which this version of macOS cannot open. Export it again with AES-256. |
| Corrupt or not a PKCS#7 file | This PKCS#7 file is corrupt or is not a PKCS#7 bundle. |
| Signed or enveloped PKCS#7 | This PKCS#7 file is signed or enveloped data, not a certificate bundle. |

A corrupt `.p12` does not ask for a password. A legacy file with the wrong password says the password is incorrect. A legacy file with `test123` either opens or shows the legacy-encryption message. It does not say the password is wrong when the cipher is the problem.

## Checklist

Open each file with File > Open, by dropping it on the window, and with Finder Open With, unless a row says otherwise. "All three" means those three ways.

| Fixture | How | Password | Expected |
| --- | --- | --- | --- |
| `leaf-aes256.p12` | All three | `test123` | One certificate, common name **CertRev Test Leaf**. The summary and the certificate list say **Private key: RSA 2048-bit**. RAW has Private Key rows Present = Yes, Type = RSA, Size = 2048-bit. No password and no key bytes anywhere on screen. Copy Certificate copies the certificate PEM only. |
| `leaf-aes256.p12` | File > Open | `nope` | The sheet stays open and says **The password is incorrect.** The field is empty again. Nothing from the file is shown. |
| `leaf-aes256.p12` | File > Open | `test123` after the wrong password above | The sheet closes and the leaf certificate opens, with the private-key line. |
| `leaf-empty-password.p12` | All three | Leave the field blank and click Open | Same leaf certificate and **Private key: RSA 2048-bit**. This file's MAC was rewritten to the zero-length blank password that macOS imports. The AES encryption already uses that empty password. |
| `leaf-empty-password.p12` | File > Open | `test123` | **The password is incorrect.** |
| `leaf-empty-password-openssl3.p12` | File > Open | Leave the field blank | **This PKCS#12 file uses a blank-password encoding that this version of macOS cannot import. Export it again and set a password.** Not the corrupt-file message, and not the wrong-password message. This is OpenSSL 3's unmodified export: two null bytes in the MAC, and a zero-length password in the AES encryption. |
| `leaf-legacy-rc2-3des.p12` | All three | `test123` | Either the leaf certificate and **Private key: RSA 2048-bit**, or the legacy RC2/3DES message. Not the wrong-password message. |
| `leaf-legacy-rc2-3des.p12` | File > Open | `nope` | **The password is incorrect.** |
| `chain-aes256.p12` | All three | `test123` | Three certificates, in this order: **CertRev Test Leaf**, **CertRev Test Intermediate CA**, **CertRev Test Root CA**. Only the leaf shows a private key. None of them say **Doesn't chain**. |
| `chain-aes256.pfx` | All three, including Finder Open With on the `.pfx` | `test123` | Same three certificates as `chain-aes256.p12`. |
| `chain.p7b` | All three | None. No sheet. | The same three names, leaf then intermediate then root. No private-key line. None say **Doesn't chain**. |
| `chain-pem.p7b` | All three | None | Same as `chain.p7b`. The file is PEM and starts with `-----BEGIN PKCS7-----`. |
| `chain-plus-unchained.p7b` | All three | None | Four certificates. Leaf, intermediate, and root stay in that relative order. **CertRev Test Unrelated** says **Doesn't chain**. The other three do not. |
| `signed.p7b` | All three | None | **This PKCS#7 file is signed or enveloped data, not a certificate bundle.** |
| `enveloped.p7b` | All three | None | The same signed-or-enveloped message. |
| `corrupt.p12` | All three | None. No sheet. | **This PKCS#12 file is corrupt or is not a PKCS#12 bundle.** |
| `corrupt.p7b` | All three | None | **This PKCS#7 file is corrupt or is not a PKCS#7 bundle.** |
| `leaf.crt` | File > Open | None | Still opens as a single PEM certificate, common name **CertRev Test Leaf**, with no private-key line. |

Also drop `leaf-aes256.p12` onto the window while `leaf.crt` is already open, enter `nope`, and confirm the leaf certificate stays on screen behind the sheet. Cancel and confirm it is still there. Open the `.p12` again with `test123` and confirm the sheet closes and the PKCS#12 contents replace it.

## A real PKCS#12 and a real PKCS#7

These files are yours. Do not commit them, attach them to an issue, or send them with a bug report. A `.p12` from Keychain Access contains a private key.

PKCS#12 from Keychain Access:

1. Open Keychain Access and select a certificate that has a private key.
2. Choose File > Export Items… and pick `.p12`.
3. Set a password you can remember.
4. In CertRev, use File > Open, drag the file onto the window, and Finder Open With.
5. Enter that password. Expect the leaf and any intermediates that were in the export, in chain order, and a private-key line with the key's type and size. The password and the key bytes must not appear. Check RAW, the summary, and Copy Certificate.
6. Try the password once with a wrong value and confirm the sheet says **The password is incorrect.**
7. Quit CertRev. The password should not have been added to Keychain by CertRev. Keychain Access should not show a new item from this open.

PKCS#7 from a CA:

1. Download a certs-only `.p7b` or `.p7c` (DER or PEM). A file that is only a signature, or S/MIME enveloped data, should instead show the signed-or-enveloped message.
2. Open it with File > Open, drag and drop, and Finder Open With. There is no password.
3. Every certificate in the bundle should be listed. When they chain, the leaf comes first and the root last. A certificate that does not connect to the others is marked **Doesn't chain**.

## Limits worth knowing

- A blank password is two PKCS#12 passwords: no password (zero bytes) and an empty BMPString (two null bytes). OpenSSL 3 writes the two null bytes into the MAC and uses zero bytes for AES. `SecPKCS12Import` treats a blank passphrase as zero bytes for both, so that unmodified file cannot be opened. CertRev reports that encoding instead of calling the file corrupt. `leaf-empty-password.p12` is the same export with the MAC rewritten to the zero-length form. The script needs `python3` for that rewrite.
- Legacy RC2/3DES support depends on the macOS version. CertRev checks the password against the PKCS#12 MAC first, then asks Security.framework to decrypt. If macOS can still decrypt those ciphers, the file opens. If it cannot, the message names RC2/3DES instead of blaming the password.
- A PKCS#12 MAC with more than 5,000,000 iterations is not checked in the app. `SecPKCS12Import` still decides, and the wrong-password and legacy messages are less precise for that file.
- A PKCS#12 file with no MAC at all uses the status code from `SecPKCS12Import`. A wrong password on that kind of file can be reported as corrupt if macOS does not return an authentication failure.
- `SecPKCS12Import` returns the identity and its certificate chain. A certificate that was inside the file but is not part of that chain can be omitted.
- PKCS#7 import is DER, including PEM-wrapped DER (`-----BEGIN PKCS7-----` or `-----BEGIN CMS-----`). Indefinite-length BER is rejected as corrupt.
- Certs-only SignedData is opened. A signature, digested data, or enveloped data is rejected even if it also carries certificates.
- Nothing is added to the keychain. `SecPKCS12Import` is called with `kSecImportToMemoryOnly`. The private key is not exported, copied, or logged. Only its type and size are kept. The UTF-16 password bytes used for the MAC are wiped after the check. The Swift `String` passed into the importer is released when that call returns; Swift does not promise that the string's storage is overwritten.
