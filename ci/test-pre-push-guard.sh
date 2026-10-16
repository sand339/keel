#!/bin/sh
# KSR-062: the public repository is recognized in every spelling GitHub
# accepts, and other remotes stay unrestricted.
set -eu

repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$repo_root"
head=$(git rev-parse HEAD)
push() {
    printf 'refs/heads/main %s refs/heads/main 0\n' "$head" | sh ci/pre-push-guard.sh public "$1" >/dev/null 2>&1
}
for url in https://github.com/sand339/keel https://github.com/Sand339/keel \
    https://github.com/sand339/keel/ https://github.com/sand339/KEEL.git/ \
    git@github.com:sand339/keel.git ssh://git@github.com/sand339/keel; do
    if push "$url"; then
        echo "pre-push guard let main through to $url" >&2
        exit 1
    fi
done
for url in https://github.com/sand339/keel-private.git https://github.com/sand339/keel-live-test; do
    push "$url" || { echo "pre-push guard refused $url" >&2; exit 1; }
done
echo "pre-push guard: ok"
