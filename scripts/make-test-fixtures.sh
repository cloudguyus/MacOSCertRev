#!/bin/bash
# Regenerates the throwaway PKCS#12 and PKCS#7 fixtures used by MacOSCertRevTests.
#
# The certificates and private keys are generated here and are not secrets.
# The PKCS#12 password is test123, or empty for the empty-password file.
# Works with the LibreSSL openssl at /usr/bin/openssl and with Homebrew OpenSSL 3.
# OpenSSL 3 needs -legacy to write RC2/3DES; LibreSSL still writes those by default
# and rejects -legacy.

set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
out="$root/MacOSCertRevTests/Fixtures/PKCS"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

if ! command -v openssl >/dev/null 2>&1; then
  echo "openssl is not on PATH" >&2
  exit 1
fi

version_line="$(openssl version)"
if printf '%s\n' "$version_line" | grep -qi LibreSSL; then
  flavor="libressl"
else
  flavor="openssl"
fi
printf 'Using %s\n' "$version_line"

rm -rf "$out"
mkdir -p "$out"
cd "$work"

cat > ca.ext <<'EOF'
basicConstraints=critical,CA:TRUE
keyUsage=critical,keyCertSign,cRLSign
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid:always
EOF

cat > leaf.ext <<'EOF'
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectAltName=DNS:leaf.example.test
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid:always
EOF

openssl req -x509 -newkey rsa:2048 -nodes \
  -keyout root.key -out root.crt -days 3650 \
  -subj "/CN=CertRev Test Root CA" \
  -addext "basicConstraints=critical,CA:TRUE" \
  -addext "keyUsage=critical,keyCertSign,cRLSign" \
  -addext "subjectKeyIdentifier=hash"

openssl req -newkey rsa:2048 -nodes \
  -keyout intermediate.key -out intermediate.csr \
  -subj "/CN=CertRev Test Intermediate CA"
openssl x509 -req -in intermediate.csr -CA root.crt -CAkey root.key -CAcreateserial \
  -out intermediate.crt -days 3650 -extfile ca.ext

openssl req -newkey rsa:2048 -nodes \
  -keyout leaf.key -out leaf.csr \
  -subj "/CN=CertRev Test Leaf"
openssl x509 -req -in leaf.csr -CA intermediate.crt -CAkey intermediate.key -CAcreateserial \
  -out leaf.crt -days 825 -extfile leaf.ext

openssl req -x509 -newkey rsa:2048 -nodes \
  -keyout unrelated.key -out unrelated.crt -days 3650 \
  -subj "/CN=CertRev Test Unrelated" \
  -addext "basicConstraints=critical,CA:FALSE" \
  -addext "subjectKeyIdentifier=hash"

cat intermediate.crt root.crt > chain-cas.crt
printf 'not a secret\n' > payload.txt

modern_args=(-keypbe AES-256-CBC -certpbe AES-256-CBC)
if [[ "$flavor" == "libressl" ]]; then
  modern_args+=(-macalg sha256)
else
  modern_args+=(-macalg SHA256)
fi

export_modern() {
  local destination="$1"
  shift
  openssl pkcs12 -export "${modern_args[@]}" "$@" -out "$destination"
}

export_legacy() {
  local destination="$1"
  shift
  if [[ "$flavor" == "libressl" ]]; then
    openssl pkcs12 -export "$@" -out "$destination"
  else
    openssl pkcs12 -export -legacy "$@" -out "$destination"
  fi
}

export_modern "$out/leaf-aes256.p12" \
  -inkey leaf.key -in leaf.crt -name "CertRev Test Leaf" -passout pass:test123
export_modern "$out/leaf-empty-password.p12" \
  -inkey leaf.key -in leaf.crt -name "CertRev Test Leaf" -passout pass:
export_legacy "$out/leaf-legacy-rc2-3des.p12" \
  -inkey leaf.key -in leaf.crt -name "CertRev Test Leaf" -passout pass:test123
export_modern "$out/chain-aes256.p12" \
  -inkey leaf.key -in leaf.crt -certfile chain-cas.crt -name "CertRev Test Leaf" -passout pass:test123
cp "$out/chain-aes256.p12" "$out/chain-aes256.pfx"

openssl crl2pkcs7 -nocrl \
  -certfile root.crt -certfile intermediate.crt -certfile leaf.crt \
  -outform DER -out "$out/chain.p7b"
openssl crl2pkcs7 -nocrl \
  -certfile root.crt -certfile intermediate.crt -certfile leaf.crt \
  -outform PEM -out "$out/chain-pem.p7b"
openssl crl2pkcs7 -nocrl \
  -certfile root.crt -certfile intermediate.crt -certfile leaf.crt -certfile unrelated.crt \
  -outform DER -out "$out/chain-plus-unchained.p7b"
openssl cms -sign -binary -in payload.txt -signer leaf.crt -inkey leaf.key \
  -outform DER -out "$out/signed.p7b"
openssl cms -encrypt -binary -in payload.txt -outform DER \
  -out "$out/enveloped.p7b" leaf.crt

printf 'this is not a pkcs12 bundle\n' > "$out/corrupt.p12"
printf 'this is not a pkcs7 bundle\n' > "$out/corrupt.p7b"

cp root.crt "$out/root.crt"
cp intermediate.crt "$out/intermediate.crt"
cp leaf.crt "$out/leaf.crt"
cp unrelated.crt "$out/unrelated.crt"
cp root.key "$out/TEST-ONLY-root.key.pem"
cp intermediate.key "$out/TEST-ONLY-intermediate.key.pem"
cp leaf.key "$out/TEST-ONLY-leaf.key.pem"
cp unrelated.key "$out/TEST-ONLY-unrelated.key.pem"
chmod 644 "$out"/*

info_for() {
  local file="$1"
  local pass="$2"
  local legacy_flag="${3:-}"
  local args=()
  if [[ -n "$legacy_flag" ]]; then
    args+=(-legacy)
  fi
  openssl pkcs12 "${args[@]}" -in "$file" -passin "pass:$pass" -info -nokeys -nocerts -noout 2>&1 || true
}

modern_info="$(info_for "$out/leaf-aes256.p12" "test123")"
printf '%s\n' "$modern_info" | grep -q "AES-256-CBC"
if printf '%s\n' "$modern_info" | grep -q "RC2"; then
  echo "modern fixture unexpectedly uses RC2" >&2
  exit 1
fi

empty_info="$(info_for "$out/leaf-empty-password.p12" "")"
printf '%s\n' "$empty_info" | grep -q "AES-256-CBC"
openssl pkcs12 -in "$out/leaf-empty-password.p12" -passin pass: -nokeys -noout >/dev/null

if [[ "$flavor" == "libressl" ]]; then
  legacy_info="$(info_for "$out/leaf-legacy-rc2-3des.p12" "test123")"
else
  legacy_info="$(info_for "$out/leaf-legacy-rc2-3des.p12" "test123" legacy)"
fi
printf '%s\n' "$legacy_info" | grep -q "RC2"
printf '%s\n' "$legacy_info" | grep -q "TripleDES"

chain_count="$(openssl pkcs12 -in "$out/chain-aes256.p12" -passin pass:test123 -nokeys | grep -c "BEGIN CERTIFICATE")"
if [[ "$chain_count" -ne 3 ]]; then
  echo "chain p12 has $chain_count certificates, expected 3" >&2
  exit 1
fi

der_count="$(openssl pkcs7 -print_certs -in "$out/chain.p7b" -inform DER | grep -c "BEGIN CERTIFICATE")"
pem_count="$(openssl pkcs7 -print_certs -in "$out/chain-pem.p7b" -inform PEM | grep -c "BEGIN CERTIFICATE")"
unchained_count="$(openssl pkcs7 -print_certs -in "$out/chain-plus-unchained.p7b" -inform DER | grep -c "BEGIN CERTIFICATE")"
if [[ "$der_count" -ne 3 || "$pem_count" -ne 3 || "$unchained_count" -ne 4 ]]; then
  echo "unexpected PKCS#7 certificate counts: der=$der_count pem=$pem_count unchained=$unchained_count" >&2
  exit 1
fi

grep -q "BEGIN PKCS7" "$out/chain-pem.p7b"

cat > "$out/README.md" <<'EOF'
# Test-only PKCS fixtures

These files are generated by `scripts/make-test-fixtures.sh`. They are throwaway
test data, not secrets. The private keys were created for this suite and do not
protect anything. Do not replace them with a real key or a real certificate.

Regenerate them with:

```
scripts/make-test-fixtures.sh
```

The script uses whichever `openssl` is on `PATH`. LibreSSL (the `/usr/bin/openssl`
shipped with macOS) and Homebrew OpenSSL 3 are both supported. OpenSSL 3 writes
the RC2/3DES file with `-legacy`. LibreSSL still writes that older encryption by
default and does not accept `-legacy`.

## Password

`test123` for every PKCS#12 file except `leaf-empty-password.p12`, which has an
empty password. Open that file by leaving the password field blank.

## Files

| File | What it is |
| --- | --- |
| `root.crt`, `intermediate.crt`, `leaf.crt` | PEM certificates. The leaf is issued by the intermediate, which is issued by the root. |
| `unrelated.crt` | A self-signed certificate that does not chain to the others. |
| `TEST-ONLY-*.key.pem` | Throwaway PKCS#8 private keys for those certificates. |
| `leaf-aes256.p12` | Leaf certificate and its private key. AES-256, password `test123`. |
| `leaf-empty-password.p12` | Same leaf. AES-256, empty password. |
| `leaf-legacy-rc2-3des.p12` | Same leaf. Legacy RC2 (certificates) and 3DES (private key), password `test123`. |
| `chain-aes256.p12` | Leaf, intermediate, and root, plus the leaf private key. AES-256, password `test123`. |
| `chain-aes256.pfx` | A copy of `chain-aes256.p12`. |
| `chain.p7b` | DER certs-only PKCS#7 of root, intermediate, and leaf. No password. |
| `chain-pem.p7b` | The same bundle as PEM (`-----BEGIN PKCS7-----`). |
| `chain-plus-unchained.p7b` | DER bundle of the chain plus `unrelated.crt`. |
| `signed.p7b` | A CMS signature, not a certificate bundle. |
| `enveloped.p7b` | CMS enveloped data, not a certificate bundle. |
| `corrupt.p12`, `corrupt.p7b` | Text that is not a valid bundle. |

Common names: `CertRev Test Leaf`, `CertRev Test Intermediate CA`, `CertRev Test Root CA`, `CertRev Test Unrelated`.
The leaf private key is RSA 2048.
EOF

printf 'Wrote fixtures to %s\n' "$out"
