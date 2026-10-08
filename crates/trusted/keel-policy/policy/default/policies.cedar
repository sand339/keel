permit (principal, action, resource);

@id("bulk-write-preexisting")
forbid (
    principal,
    action == Action::"write",
    resource
) when {
    context.distinct_files_written_60s >= 20 &&
    !context.target_created_by_vertex
};

@id("write-after-registry-contact")
forbid (
    principal,
    action == Action::"write",
    resource
) when {
    context.registries_contacted
};

@id("repeated-denials-same-scope")
forbid (principal, action, resource) when {
    context.recent_behavioral_denials_in_scope >= 3
};

@id("push-without-structured-intent")
forbid (
    principal,
    action == Action::"push",
    resource
) when {
    !context.intent.allow_push_branch
};

@id("push-after-unowned-host")
forbid (
    principal,
    action == Action::"push",
    resource
) when {
    !context.own_domains.containsAll(context.source_hosts)
};

@id("deny:force-push")
forbid (
    principal,
    action == Action::"push",
    resource
) when {
    context.intent.deny_force_push &&
    context.target_is_force_push
};
