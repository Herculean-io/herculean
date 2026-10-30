#!/bin/sh
# Install the herculean binary from a GitHub release, checked against the release's SHA256SUMS.
#
#   curl -fsSL https://raw.githubusercontent.com/Herculean-io/herculean/main/install.sh | sh
#
# HERCULEAN_VERSION      release tag to install, such as v0.2.0 (default: the latest release)
# HERCULEAN_INSTALL_DIR  where to put the binary (default: ~/.local/bin)
# HERCULEAN_DOWNLOAD_URL a mirror holding the release archives and SHA256SUMS (default: the GitHub release)
#
# Exits 3 when the archive fails its SHA256SUMS check, so a caller (action.yml) can tell a corrupt
# or tampered release from a missing one.
set -eu

repo=Herculean-io/herculean
version=${HERCULEAN_VERSION:-latest}
dir=${HERCULEAN_INSTALL_DIR:-$HOME/.local/bin}

case "$(uname -s)-$(uname -m)" in
  Linux-x86_64) target=x86_64-unknown-linux-gnu ;;
  Linux-aarch64 | Linux-arm64) target=aarch64-unknown-linux-gnu ;;
  Darwin-x86_64) target=x86_64-apple-darwin ;;
  Darwin-arm64) target=aarch64-apple-darwin ;;
  *)
    echo "herculean: no prebuilt binary for $(uname -s) $(uname -m)." >&2
    echo "Build it instead: cargo install --locked --git https://github.com/$repo herculean" >&2
    exit 1
    ;;
esac

if [ -n "${HERCULEAN_DOWNLOAD_URL:-}" ]; then
  base=$HERCULEAN_DOWNLOAD_URL
elif [ "$version" = latest ]; then
  base=https://github.com/$repo/releases/latest/download
else
  base=https://github.com/$repo/releases/download/$version
fi
asset=herculean-$target.tar.gz

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
curl -fsSL -o "$tmp/$asset" "$base/$asset"
curl -fsSL -o "$tmp/SHA256SUMS" "$base/SHA256SUMS"

want=$(awk -v f="$asset" '$2 == f { print $1 }' "$tmp/SHA256SUMS")
if command -v sha256sum >/dev/null 2>&1; then
  got=$(sha256sum "$tmp/$asset" | awk '{ print $1 }')
else
  got=$(shasum -a 256 "$tmp/$asset" | awk '{ print $1 }')
fi
if [ -z "$want" ] || [ "$want" != "$got" ]; then
  echo "herculean: checksum mismatch for $asset; not installing." >&2
  exit 3
fi

tar -xzf "$tmp/$asset" -C "$tmp"
# A plain assignment, so set -e stops here, before installing, if the binary cannot run on this machine.
version=$("$tmp/herculean-$target/herculean" --version)
mkdir -p "$dir"
cp "$tmp/herculean-$target/herculean" "$dir/herculean"
chmod 755 "$dir/herculean"
echo "Installed $version to $dir/herculean"
case ":$PATH:" in
  *":$dir:"*) ;;
  *) echo "Add $dir to your PATH to use it." ;;
esac
