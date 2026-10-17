#!/bin/sh
# Packages an installed Keel runtime as a release tarball for this platform.
#
# The checkout must be clean: the release is built here, from HEAD, by
# `keel setup` into a fresh install directory, so what ships is what HEAD
# names and nothing installed earlier (KSR-050, KSR-061). The release holds
# that install (bin/ and images/), with SHA256SUMS, PLATFORM, VERSION, and
# install.sh. Unpacked, `./install.sh` runs the bundled `keel setup
# --prebuilt`, which checks every file against SHA256SUMS before installing,
# so a user needs neither Docker nor a toolchain. The tarball itself lands in
# target/dist with its own .sha256. Both detect corruption in transit; neither
# proves who built the release, since the sums ship beside what they cover
# (KSR-051).
set -eu

repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
sha256() {
    if command -v sha256sum >/dev/null 2>&1; then sha256sum "$@"; else shasum -a 256 "$@"; fi
}
if [ -n "$(git -C "$repo_root" status --porcelain --untracked-files=no)" ]; then
    echo "the checkout has uncommitted changes; a release is built from HEAD only" >&2
    exit 1
fi
if [ "${KEEL_RELEASE_SIGN:-0}" = 1 ] && ! command -v cosign >/dev/null 2>&1; then
    echo "KEEL_RELEASE_SIGN=1 needs cosign (https://docs.sigstore.dev/cosign/system_config/installation/)" >&2
    exit 1
fi
build_root=$(mktemp -d "${TMPDIR:-/tmp}/keel-release.XXXXXX")
trap 'rm -rf "$build_root"' EXIT
install_root="$build_root/install"
(
    cd "$repo_root"
    # The built binary, not `cargo run`: cargo's LD_LIBRARY_PATH makes the
    # renderer's self-test refuse to spawn on Linux.
    cargo build --locked --release -q -p keel-cli --bin keel
    KEEL_INSTALL_DIR="$install_root" KEEL_BIN_DIR="$build_root/bin" \
        KEEL_CONFIG="$build_root/config.json" ./target/release/keel setup
)
case "$(uname -s)" in
Darwin) os=macos ;;
Linux) os=linux ;;
*) echo "unsupported host: $(uname -s)" >&2; exit 1 ;;
esac
arch=$(uname -m)
[ "$arch" = arm64 ] && arch=aarch64
platform="$os-$arch"
version=$(sed -n 's/^version = "\(.*\)"$/\1/p' "$repo_root/Cargo.toml" | head -n 1)
commit=$(git -C "$repo_root" rev-parse --short HEAD)
release_version="${KEEL_RELEASE_VERSION:-$version+$commit}"
name="keel-$release_version-$platform"
dist="$repo_root/target/dist"
stage="$dist/$name"

for directory in bin images; do
    if [ ! -d "$install_root/$directory" ]; then
        echo "no installed runtime at $install_root; run keel setup first" >&2
        exit 1
    fi
done
rm -rf "$stage"
mkdir -p "$stage"
cp -Rp "$install_root/bin" "$install_root/images" "$stage/"
printf '%s\n' "$platform" > "$stage/PLATFORM"
printf '%s\n' "$release_version" > "$stage/VERSION"
cat > "$stage/install.sh" <<'SH'
#!/bin/sh
# Installs this Keel release for the current user, after checking every file
# against SHA256SUMS. That detects a damaged download; it does not prove who
# built the release.
set -eu
here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
"$here/bin/keel" setup --prebuilt "$here"
SH
chmod 0755 "$stage/install.sh"
(
    cd "$stage"
    find ./bin ./images -type f | LC_ALL=C sort | while read -r file; do sha256 "$file"; done
) > "$stage/SHA256SUMS"

tar -C "$dist" -czf "$dist/$name.tar.gz" "$name"
(cd "$dist" && sha256 "$name.tar.gz" > "$name.tar.gz.sha256")
rm -rf "$stage"
echo "packaged $dist/$name.tar.gz"
cat "$dist/$name.tar.gz.sha256"

# KSR-051: with KEEL_RELEASE_SIGN=1, sign the tarball with Sigstore's keyless
# flow. cosign opens a browser to log in, binds a short-lived certificate to
# that identity, and records the signature in the public transparency log;
# no signing key is kept anywhere. The bundle is published beside the
# tarball, and a user checks it with cosign before unpacking.
if [ "${KEEL_RELEASE_SIGN:-0}" = 1 ]; then
    cosign sign-blob --yes --bundle "$dist/$name.tar.gz.sigstore.json" "$dist/$name.tar.gz"
    echo "signed $dist/$name.tar.gz.sigstore.json"
fi
