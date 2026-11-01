#!/bin/bash
# Xcode 27 builds swift-crypto's Crypto target as a dynamic framework and then
# links X509 against a static Crypto.o that was never produced. Declaring the
# products static makes that object file exist. Checked-out packages are
# read-only, so a required patch rewrites Package.swift and no other file.
#
# The edit is in Package.swift, which is shared by every architecture. One
# patch covers both slices of a universal (arm64 and x86_64) build.
#
# Two different directories are called DerivedData:
# - The release workflow's -derivedDataPath (build/DerivedData) contains
#   SourcePackages directly. FORCE_STATIC_CRYPTO_STRICT=1, or that kind of
#   path with no MacOSCertRev-<hash> child, must fail when the checkout is
#   missing. A home DerivedData checkout must not hide that miss.
# - A scheme pre-action exports DERIVED_DATA_DIR as the DerivedData container
#   (~/Library/Developer/Xcode/DerivedData). SourcePackages lives in
#   MacOSCertRev-<hash> under that container. The hash folder is also what
#   BUILD_DIR / SYMROOT / OBJROOT point at when Xcode has filled them in.
#
# This script never runs xcodebuild. A nested resolve races the outer build:
# CpResource copies PrivacyInfo.xcprivacy out of the swift-crypto checkout
# while that checkout is being rewritten. The scheme pre-action therefore
# patches only a Package.swift that is already on disk, and exits 0 when the
# checkout does not exist yet. The release job resolves first, then runs this
# script with FORCE_STATIC_CRYPTO_STRICT=1, which fails if it cannot patch.
set -euo pipefail

patch_one() {
  local package_swift="$1"
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
if not applied:
    print(f"already static: {path}")
    sys.exit(0)
# Only Package.swift changes, and only when the library lines are not already
# static. Leave every other checkout file, including PrivacyInfo.xcprivacy, alone.
mode = path.stat().st_mode
if not (mode & 0o200):
    path.chmod(mode | 0o200)
path.write_text(text)
print(f"patched {path}")
PY
}

package_swift_for() {
  printf '%s\n' "${1%/}/SourcePackages/checkouts/swift-crypto/Package.swift"
}

# BUILD_DIR and SYMROOT end in /Build/Products, sometimes with /Debug after
# that. OBJROOT ends in /Build/Intermediates.noindex. The project derived data
# root is the directory that contains Build, not the DerivedData container.
derived_data_from_build_path() {
  local path="${1%/}"
  case "$path" in
    */Build/Products|*/Build/Products/*)
      printf '%s\n' "${path%%/Build/Products*}"
      ;;
    */Build/Intermediates.noindex|*/Build/Intermediates.noindex/*)
      printf '%s\n' "${path%%/Build/Intermediates.noindex*}"
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

has_project_children() {
  local root="$1"
  local child
  [ -d "$root" ] || return 1
  shopt -s nullglob
  for child in "$root"/MacOSCertRev-*; do
    if [ -d "$child" ]; then
      return 0
    fi
  done
  return 1
}

add_project_children() {
  local root="$1"
  local child
  [ -d "$root" ] || return 0
  shopt -s nullglob
  for child in "$root"/MacOSCertRev-*; do
    if [ -d "$child" ]; then
      add_root "$child"
    fi
  done
}

# A -derivedDataPath directory holds SourcePackages or Build directly.
# MacOSCertRev-<hash> is the per-project folder inside the default container.
is_project_root() {
  local root="${1%/}"
  local base
  # The container can contain a stray Build directory. It is still the folder
  # that holds MacOSCertRev-<hash>, not the directory xcodebuild -derivedDataPath
  # would use.
  if is_xcode_container "$root"; then
    return 1
  fi
  base="$(basename "$root")"
  case "$base" in
    MacOSCertRev-*) return 0 ;;
  esac
  if [ -d "$root/SourcePackages" ] || [ -d "$root/Build" ]; then
    return 0
  fi
  return 1
}

# Xcode's scheme environment sets DERIVED_DATA_DIR to the container that holds
# MacOSCertRev-<hash>, including when that container is still empty.
is_xcode_container() {
  local root="${1%/}"
  if [ "$root" = "$HOME/Library/Developer/Xcode/DerivedData" ]; then
    return 0
  fi
  if has_project_children "$root"; then
    return 0
  fi
  return 1
}

consider_build_setting() {
  local value="${1:-}"
  local inferred
  [ -n "$value" ] || return 0
  inferred="$(derived_data_from_build_path "$value")" || return 0
  if is_project_root "$inferred"; then
    if [ -z "$active_root" ]; then
      active_root="$inferred"
    fi
    add_root "$inferred"
  else
    add_project_children "$inferred"
  fi
}

collect_roots() {
  local dd repo_dd
  roots=()
  active_root=""
  strict=0
  if [ "${FORCE_STATIC_CRYPTO_STRICT:-}" = 1 ]; then
    strict=1
    if [ -z "${DERIVED_DATA_DIR:-}" ]; then
      echo "error: FORCE_STATIC_CRYPTO_STRICT=1 requires DERIVED_DATA_DIR." >&2
      echo "The release workflow sets it to the xcodebuild -derivedDataPath directory (build/DerivedData)." >&2
      exit 1
    fi
    active_root="${DERIVED_DATA_DIR%/}"
    add_root "$active_root"
    return 0
  fi
  if [ -n "${DERIVED_DATA_DIR:-}" ]; then
    dd="${DERIVED_DATA_DIR%/}"
    if is_xcode_container "$dd"; then
      add_project_children "$dd"
    else
      strict=1
      active_root="$dd"
      add_root "$dd"
      return 0
    fi
  fi
  consider_build_setting "${BUILD_DIR:-}"
  consider_build_setting "${SYMROOT:-}"
  consider_build_setting "${OBJROOT:-}"
  add_project_children "$HOME/Library/Developer/Xcode/DerivedData"
  repo_dd="$repo_root/build/DerivedData"
  if [ -f "$(package_swift_for "$repo_dd")" ]; then
    add_root "$repo_dd"
  fi
}

fail_not_applied() {
  local root
  echo "error: the Xcode 27 swift-crypto static-library workaround was not applied." >&2
  if [ "${#roots[@]}" -eq 0 ]; then
    echo "Searched no project DerivedData directories." >&2
  else
    echo "Searched:" >&2
    for root in "${roots[@]}"; do
      echo "  $root" >&2
    done
  fi
  if [ "$strict" -eq 1 ]; then
    echo "This DerivedData path is the release -derivedDataPath directory. A checkout under ~/Library/Developer/Xcode/DerivedData does not satisfy it." >&2
  fi
  exit 1
}

apply_patches() {
  local root package_swift
  found=0
  missing_active=0
  if [ "${#roots[@]}" -eq 0 ]; then
    return 0
  fi
  for root in "${roots[@]}"; do
    package_swift="$(package_swift_for "$root")"
    if [ ! -f "$package_swift" ]; then
      echo "swift-crypto Package.swift not found at $package_swift" >&2
      if [ "$strict" -eq 1 ] || [ "$root" = "$active_root" ]; then
        missing_active=1
      fi
      continue
    fi
    patch_one "$package_swift" || exit 1
    found=$((found + 1))
  done
}

script_dir="$(cd "$(dirname "$0")" && pwd)"
repo_root="$(cd "$script_dir/.." && pwd)"
roots=()
active_root=""
strict=0
found=0
missing_active=0

collect_roots
apply_patches

if [ "$strict" -eq 1 ]; then
  if [ "$found" -eq 0 ] || [ "$missing_active" -eq 1 ]; then
    fail_not_applied
  fi
elif [ "$found" -eq 0 ]; then
  echo "swift-crypto checkout is not present yet. Leaving the package unchanged."
  exit 0
fi

echo "swift-crypto static-library workaround is in place (${found} checkout(s))."
