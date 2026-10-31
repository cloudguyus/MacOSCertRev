#!/bin/bash
# Xcode 27 builds swift-crypto's Crypto target as a dynamic framework and then
# links X509 against a static Crypto.o that was never produced. Declaring the
# products static makes that object file exist. Checked-out packages are
# read-only, so this rewrites the local checkout before the build graph loads.
#
# The edit is in Package.swift, which is shared by every architecture. One
# patch covers both slices of a universal (arm64 and x86_64) build.
#
# This exits non-zero when it cannot find swift-crypto or the library
# declarations are neither the upstream lines nor already static. A skipped
# patch used to exit 0, and the release continued until the link failed.
set -euo pipefail

patch_one() {
  local package_swift="$1"
  chmod u+w "$package_swift"
  python3 - "$package_swift" <<'PY'
import pathlib, sys
path = pathlib.Path(sys.argv[1])
text = path.read_text()
replacements = (
    (
        '.library(name: "Crypto", targets: ["Crypto"]),',
        '.library(name: "Crypto", type: .static, targets: ["Crypto"]),',
    ),
    (
        '.library(name: "_CryptoExtras", targets: ["_CryptoExtras"]),',
        '.library(name: "_CryptoExtras", type: .static, targets: ["_CryptoExtras"]),',
    ),
)
missing = []
applied = False
for old, new in replacements:
    if old in text:
        text = text.replace(old, new)
        applied = True
    elif new not in text:
        missing.append(old)
if missing:
    print(
        "error: swift-crypto Package.swift is missing the Crypto or "
        "_CryptoExtras declarations this workaround patches, and they are "
        "not already static:",
        file=sys.stderr,
    )
    for line in missing:
        print(f"  {line}", file=sys.stderr)
    print(f"  in {path}", file=sys.stderr)
    sys.exit(1)
if applied:
    path.write_text(text)
    print(f"patched {path}")
else:
    print(f"already static: {path}")
PY
}

# BUILD_DIR and SYMROOT end in /Build/Products. OBJROOT ends in
# /Build/Intermediates.noindex. The package checkout is the parent of Build.
derived_data_from_build_path() {
  local path="${1%/}"
  case "$path" in
    */Build/Products|*/Build/Intermediates.noindex)
      dirname "$(dirname "$path")"
      ;;
    *)
      return 1
      ;;
  esac
}

root_seen() {
  local candidate="$1"
  local existing
  if [ "${#roots[@]}" -eq 0 ]; then
    return 1
  fi
  for existing in "${roots[@]}"; do
    if [ "$existing" = "$candidate" ]; then
      return 0
    fi
  done
  return 1
}

add_root() {
  local root="${1%/}"
  if [ -z "$root" ]; then
    return 0
  fi
  if root_seen "$root"; then
    return 0
  fi
  roots+=("$root")
}

roots=()
# When the caller names a DerivedData directory, that directory is the only
# one that counts. A checkout under ~/Library must not hide a miss there.
explicit=0

if [ -n "${DERIVED_DATA_DIR:-}" ]; then
  explicit=1
  add_root "$DERIVED_DATA_DIR"
else
  if [ -n "${BUILD_DIR:-}" ]; then
    if inferred="$(derived_data_from_build_path "$BUILD_DIR")"; then
      explicit=1
      add_root "$inferred"
    fi
  fi
  if [ -n "${SYMROOT:-}" ]; then
    if inferred="$(derived_data_from_build_path "$SYMROOT")"; then
      explicit=1
      add_root "$inferred"
    fi
  fi
  if [ -n "${OBJROOT:-}" ]; then
    if inferred="$(derived_data_from_build_path "$OBJROOT")"; then
      explicit=1
      add_root "$inferred"
    fi
  fi
fi

if [ "$explicit" -eq 0 ]; then
  script_dir="$(cd "$(dirname "$0")" && pwd)"
  repo_derived="$(cd "$script_dir/.." && pwd)/build/DerivedData"
  if [ -d "$repo_derived" ]; then
    add_root "$repo_derived"
  fi
  shopt -s nullglob
  for derived in "$HOME/Library/Developer/Xcode/DerivedData"/MacOSCertRev-*; do
    add_root "$derived"
  done
fi

if [ "${#roots[@]}" -eq 0 ]; then
  echo "error: force-static-crypto.sh found no DerivedData directory to search." >&2
  echo "Set DERIVED_DATA_DIR to the directory passed as xcodebuild -derivedDataPath (build/DerivedData in the release workflow)." >&2
  exit 1
fi

found=0
missing_required=0
for root in "${roots[@]}"; do
  package_swift="$root/SourcePackages/checkouts/swift-crypto/Package.swift"
  if [ ! -f "$package_swift" ]; then
    if [ "$explicit" -eq 1 ]; then
      echo "error: swift-crypto Package.swift not found at $package_swift" >&2
      missing_required=1
    fi
    continue
  fi
  patch_one "$package_swift"
  found=$((found + 1))
done

if [ "$found" -eq 0 ] || [ "$missing_required" -eq 1 ]; then
  echo "error: the Xcode 27 swift-crypto static-library workaround was not applied." >&2
  echo "Searched:" >&2
  for root in "${roots[@]}"; do
    echo "  $root" >&2
  done
  exit 1
fi

echo "swift-crypto static-library workaround is in place (${found} checkout(s))."
