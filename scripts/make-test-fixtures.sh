#!/bin/bash
# Regenerates the throwaway PKCS#12 and PKCS#7 fixtures used by MacOSCertRevTests.
#
# The certificates and private keys are generated here and are not secrets.
# The PKCS#12 password is test123, or empty for the empty-password files.
# Works with the LibreSSL openssl at /usr/bin/openssl and with Homebrew OpenSSL 3.
# OpenSSL 3 needs -legacy to write RC2/3DES; LibreSSL still writes those by default
# and rejects -legacy.
#
# Rewriting the blank-password MAC needs python3. OpenSSL 3's `pass:` export
# puts two null bytes in the MAC and a zero-length password in the AES
# encryption. SecPKCS12Import treats a blank passphrase as zero-length for
# both, so the script keeps one unmodified OpenSSL file and rewrites the
# other MAC to the zero-length form Apple accepts.

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

# Self-signed EC P-256 leaf, no CA. Matches a one-identity Keychain Access export.
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
  -keyout keychain-ec.key -out keychain-ec.crt -days 3650 \
  -subj "/CN=CertRev Keychain Style"

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

# Apple's `security export -f pkcs12` uses RC2-40 for certificates, 3DES for the
# key, SHA-1 for the MAC, encryption iteration 2048, and MAC iteration 1.
# OpenSSL's -iter sets both, so the MAC iteration is rewritten to 1 afterwards.
export_keychain_style() {
  local destination="$1"
  local macalg="SHA1"
  if [[ "$flavor" == "libressl" ]]; then
    macalg="sha1"
  fi
  local args=(
    -inkey keychain-ec.key -in keychain-ec.crt
    -name "CertRev Keychain Style"
    -certpbe PBE-SHA1-RC2-40 -keypbe PBE-SHA1-3DES
    -macalg "$macalg" -iter 2048
    -passout pass:test123
  )
  if [[ "$flavor" == "libressl" ]]; then
    openssl pkcs12 -export "${args[@]}" -out "$destination"
  else
    openssl pkcs12 -export -legacy "${args[@]}" -out "$destination"
  fi
  rewrite_mac_iterations "$destination" 1
}

rewrite_mac_iterations() {
  local file="$1"
  local iterations="$2"
  if ! command -v python3 >/dev/null 2>&1; then
    echo "python3 is required to set the MAC iteration count on $file" >&2
    exit 1
  fi
  python3 - "$file" "$iterations" <<'PY'
import hashlib, hmac, pathlib, sys
path = pathlib.Path(sys.argv[1])
iterations = int(sys.argv[2])
data = bytearray(path.read_bytes())

def parse_tl(buf, i):
    tag = buf[i]
    i += 1
    n = buf[i]
    i += 1
    if n & 0x80:
        length_bytes = n & 0x7F
        length = int.from_bytes(buf[i:i + length_bytes], "big")
        i += length_bytes
    else:
        length = n
    return tag, i, i + length

def children(buf, start, end):
    nodes = []
    index = start
    while index < end:
        tag, content, end_index = parse_tl(buf, index)
        nodes.append((tag, content, end_index, index))
        index = end_index
    return nodes

def encode_length(length):
    if length < 128:
        return bytes([length])
    encoded = length.to_bytes((length.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(encoded)]) + encoded

def encode_tlv(tag, content):
    return bytes([tag]) + encode_length(len(content)) + content

def expand(src, block):
    if not src:
        return b""
    size = ((len(src) + block - 1) // block) * block
    out = b""
    while len(out) < size:
        out += src
    return out[:size]

_, content, end = parse_tl(data, 0)
parts = children(data, content, end)
auth = children(data, parts[1][1], parts[1][2])
explicit = children(data, auth[1][1], auth[1][2])
if explicit[0][0] != 0x04:
    raise SystemExit("keychain-style file has no authenticated safe")
mac_input = bytes(data[explicit[0][1]:explicit[0][2]])
mac_parts = children(data, parts[2][1], parts[2][2])
digest_info = children(data, mac_parts[0][1], mac_parts[0][2])
digest_start, digest_end = digest_info[1][1], digest_info[1][2]
if digest_end - digest_start != 20:
    raise SystemExit("keychain-style MAC is not SHA-1")
salt = bytes(data[mac_parts[1][1]:mac_parts[1][2]])
password = "test123".encode("utf-16-be") + b"\x00\x00"
block = 64
material = expand(salt, block) + expand(password, block)
digest = hashlib.sha1(bytes([3]) * block + material).digest()
for _ in range(1, iterations):
    digest = hashlib.sha1(digest).digest()
mac = hmac.new(digest, mac_input, hashlib.sha1).digest()
data[digest_start:digest_end] = mac
digest_info_bytes = bytes(data[mac_parts[0][3]:mac_parts[0][2]])
salt_tlv = bytes(data[mac_parts[1][3]:mac_parts[1][2]])
iteration_bytes = iterations.to_bytes((iterations.bit_length() + 7) // 8, "big")
if iteration_bytes[0] & 0x80:
    iteration_bytes = b"\x00" + iteration_bytes
mac_data = encode_tlv(0x30, digest_info_bytes + salt_tlv + encode_tlv(0x02, iteration_bytes))
version = bytes(data[parts[0][3]:parts[0][2]])
auth_safe = bytes(data[parts[1][3]:parts[1][2]])
path.write_bytes(encode_tlv(0x30, version + auth_safe + mac_data))
PY
}

export_modern "$out/leaf-aes256.p12" \
  -inkey leaf.key -in leaf.crt -name "CertRev Test Leaf" -passout pass:test123
export_legacy "$out/leaf-legacy-rc2-3des.p12" \
  -inkey leaf.key -in leaf.crt -name "CertRev Test Leaf" -passout pass:test123
export_keychain_style "$out/keychain-style-rc2-40-ec.p12"
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

# Replace the MAC digest so it matches a zero-length password. The AES
# encryption is left as OpenSSL wrote it (PBKDF2 over a zero-length password).
rewrite_blank_password_mac() {
  local file="$1"
  if ! command -v python3 >/dev/null 2>&1; then
    echo "python3 is required to rewrite the blank-password MAC in $file" >&2
    exit 1
  fi
  python3 - "$file" <<'PY'
import hashlib, hmac, pathlib, sys
path = pathlib.Path(sys.argv[1])
data = bytearray(path.read_bytes())

def parse_tl(buf, i):
    tag = buf[i]
    i += 1
    n = buf[i]
    i += 1
    if n & 0x80:
        length_bytes = n & 0x7F
        length = int.from_bytes(buf[i:i + length_bytes], "big")
        i += length_bytes
    else:
        length = n
    return tag, i, i + length

def children(buf, start, end):
    nodes = []
    index = start
    while index < end:
        tag, content, end_index = parse_tl(buf, index)
        nodes.append((tag, content, end_index))
        index = end_index
    return nodes

_, content, end = parse_tl(data, 0)
parts = children(data, content, end)
auth = children(data, parts[1][1], parts[1][2])
explicit = children(data, auth[1][1], auth[1][2])
if explicit[0][0] != 0x04:
    raise SystemExit("blank-password file has no authenticated-safe octet string")
mac_input = bytes(data[explicit[0][1]:explicit[0][2]])
mac_parts = children(data, parts[2][1], parts[2][2])
digest_info = children(data, mac_parts[0][1], mac_parts[0][2])
digest_start, digest_end = digest_info[1][1], digest_info[1][2]
if digest_end - digest_start != 32:
    raise SystemExit("blank-password MAC is not SHA-256")
salt = bytes(data[mac_parts[1][1]:mac_parts[1][2]])
iterations = int.from_bytes(data[mac_parts[2][1]:mac_parts[2][2]], "big")

def expand(src, block):
    if not src:
        return b""
    size = ((len(src) + block - 1) // block) * block
    out = b""
    while len(out) < size:
        out += src
    return out[:size]

def derive(password):
    block = 64
    diversified = bytes([3]) * block
    material = bytearray(expand(salt, block) + expand(password, block))
    digest = hashlib.sha256(diversified + material).digest()
    for _ in range(1, iterations):
        digest = hashlib.sha256(digest).digest()
    return digest

zero_length = hmac.new(derive(b""), mac_input, hashlib.sha256).digest()
two_null = hmac.new(derive(b"\x00\x00"), mac_input, hashlib.sha256).digest()
current = bytes(data[digest_start:digest_end])
if current != two_null:
    raise SystemExit("expected OpenSSL's two-null blank-password MAC before rewriting")
data[digest_start:digest_end] = zero_length
path.write_bytes(data)
PY
}

export_modern "$out/leaf-empty-password-openssl3.p12" \
  -inkey leaf.key -in leaf.crt -name "CertRev Test Leaf" -passout pass:
# Unmodified OpenSSL export. Its MAC is the two-null BMPString, which
# SecPKCS12Import rejects for a blank passphrase.
cp "$out/leaf-empty-password-openssl3.p12" "$out/leaf-empty-password.p12"
rewrite_blank_password_mac "$out/leaf-empty-password.p12"
chmod 644 "$out/leaf-empty-password.p12" "$out/leaf-empty-password-openssl3.p12"

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
default and does not accept `-legacy`. Rewriting the blank-password MAC also
needs `python3`.

## Password

`test123` for every PKCS#12 file except the two blank-password files. Open those
by leaving the password field blank.

`leaf-empty-password.p12` is the OpenSSL 3 AES export with its MAC replaced by
the zero-length password form. That is the blank passphrase `SecPKCS12Import`
uses, and the AES encryption already uses that same empty password. This is the
file the app is expected to open.

`leaf-empty-password-openssl3.p12` is the same export before that rewrite.
OpenSSL writes two null bytes into the MAC and a zero-length password into the
AES encryption. A blank passphrase on macOS does not match that MAC, so CertRev
reports a blank-password encoding it cannot import instead of calling the file
corrupt.

## Files

| File | What it is |
| --- | --- |
| `root.crt`, `intermediate.crt`, `leaf.crt` | PEM certificates. The leaf is issued by the intermediate, which is issued by the root. |
| `unrelated.crt` | A self-signed certificate that does not chain to the others. |
| `TEST-ONLY-*.key.pem` | Throwaway PKCS#8 private keys for those certificates. |
| `leaf-aes256.p12` | Leaf certificate and its private key. AES-256, password `test123`. |
| `leaf-empty-password.p12` | Same leaf. AES-256, blank password, MAC rewritten to the zero-length form macOS imports. |
| `leaf-empty-password-openssl3.p12` | Same leaf before that rewrite. OpenSSL's split blank-password encoding. |
| `leaf-legacy-rc2-3des.p12` | Same leaf. Legacy RC2 (certificates) and 3DES (private key), password `test123`. |
| `keychain-style-rc2-40-ec.p12` | Self-signed EC P-256 leaf, no CA, friendly name set. Certificates use PBE-SHA1-RC2-40, the key uses PBE-SHA1-3DES, and the MAC is SHA-1 with 1 iteration. Password `test123`. This is the shape of `security export -f pkcs12`. |
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
