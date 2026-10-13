#!/bin/sh
# Packages an installed Keel runtime as a release tarball for this platform.
#
# Run `keel setup` from the checkout first. The release holds exactly what
# that installed (bin/ and images/), with SHA256SUMS, PLATFORM, VERSION, and
# install.sh. Unpacked, `./install.sh` runs the bundled `keel setup
# --prebuilt`, which checks every file against SHA256SUMS before installing,
# so a user needs neither Docker nor a toolchain. The tarball itself lands in
# target/dist with its own .sha256.
set -eu

repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
sha256() {
    if command -v sha256sum >/dev/null 2>&1; then sha256sum "$@"; else shasum -a 256 "$@"; fi
}
install_root="${KEEL_INSTALL_DIR:-$HOME/.local/share/keel}"
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
# against SHA256SUMS.
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
