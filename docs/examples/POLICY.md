# Keel example policy

This policy applies to `example-org/keel-live-test`.

Allow ordinary pushes to non-default feature branches and pull-request creation.
Allow outbound access to `docs.rs`.

Never allow a force push.

Require operator review before a push whenever the provenance floor is below
rank 2. Require review before writing after a package registry has been
contacted. Deny publication after three denied actions.

Treat the first argument to `cp` as a read path and the second as a write path.
