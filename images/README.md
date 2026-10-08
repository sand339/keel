# Keel base image

`build-base-image.sh` layers a verified harness and the public Keel CA onto a
pinned Linux initramfs. It performs no downloads. Every input must be supplied
with its SHA-256 digest:

```sh
images/build-base-image.sh \
  BASE_INITRAMFS BASE_SHA256 \
  HARNESS.tar.gz HARNESS_SHA256 \
  KEEL_CA.pem CA_SHA256 \
  OUTPUT.cpio.gz
```

The harness archive is extracted under `/opt/keel/harness` and must provide
executable `bin/keel-harness` and `bin/git` files. Absolute paths, parent
traversal, special files, hard links, and escaping symbolic links are rejected.

At boot, the image:

1. submits the existing network preflight before configuring synthetic
   networking;
2. maps `10.0.0.1` to loopback and answers DNS A queries with that address;
3. relays ports 80 and 443 only to host vsock port 5001;
4. relays Git smart HTTP on port 9418 only to host vsock port 5002;
5. installs the public CA and standard client trust-store variables; and
6. rewrites `/workspace`'s `origin` to
   `http://10.0.0.1:9418/origin` before launching the harness.

The CA private key is never an image input. The output uses stable ordering,
metadata, inode numbers, and gzip headers, so identical inputs produce
byte-identical images.
