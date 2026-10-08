#!/bin/sh
# Keeps the private development history out of the public repository.
#
# To github.com/sand339/keel (public), only the local `public` branch may be
# pushed, and only while it shares no history with `main`. Every other
# remote is unrestricted.
remote_url=$2

case "$remote_url" in
    *github.com/sand339/keel | *github.com/sand339/keel.git | \
    *github.com:sand339/keel | *github.com:sand339/keel.git) ;;
    *) exit 0 ;;
esac

zero=0000000000000000000000000000000000000000
while read -r local_ref local_sha remote_ref remote_sha; do
    if [ "$local_sha" = "$zero" ]; then
        echo "pre-push: refusing to delete $remote_ref on the public repository" >&2
        exit 1
    fi
    if [ "$local_ref" != "refs/heads/public" ]; then
        echo "pre-push: only the 'public' branch may be pushed to the public repository (got $local_ref)" >&2
        exit 1
    fi
    if git merge-base "$local_sha" refs/heads/main >/dev/null 2>&1; then
        echo "pre-push: 'public' shares history with 'main'; refusing to publish private history" >&2
        exit 1
    fi
done
exit 0
