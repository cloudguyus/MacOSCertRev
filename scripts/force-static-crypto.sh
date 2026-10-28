#!/bin/bash
# Xcode 27 builds swift-crypto's Crypto target as a dynamic framework and then
# links X509 against a static Crypto.o that was never produced. Declaring the
# products static makes that object file exist. Checked-out packages are
# read-only, so this rewrites the local checkout before the build graph loads.
set -euo pipefail

patch_one() {
  local package_swift="$1"
  [ -f "$package_swift" ] || return 0
  chmod u+w "$package_swift"
  python3 - "$package_swift" <<'PY'
import pathlib, sys
path = pathlib.Path(sys.argv[1])
text = path.read_text()
replacements = {
    '.library(name: "Crypto", targets: ["Crypto"]),':
        '.library(name: "Crypto", type: .static, targets: ["Crypto"]),',
    '.library(name: "_CryptoExtras", targets: ["_CryptoExtras"]),':
        '.library(name: "_CryptoExtras", type: .static, targets: ["_CryptoExtras"]),',
}
updated = text
for old, new in replacements.items():
    updated = updated.replace(old, new)
if updated != text:
    path.write_text(updated)
    print(f"patched {path}")
PY
}

roots=()
if [ -n "${DERIVED_DATA_DIR:-}" ]; then
  roots+=("$DERIVED_DATA_DIR")
fi
shopt -s nullglob
for derived in "$HOME/Library/Developer/Xcode/DerivedData"/MacOSCertRev-*; do
  roots+=("$derived")
done

seen=""
for root in "${roots[@]}"; do
  package_swift="$root/SourcePackages/checkouts/swift-crypto/Package.swift"
  case " $seen " in
    *" $package_swift "*) continue ;;
  esac
  seen="$seen $package_swift"
  patch_one "$package_swift"
done
