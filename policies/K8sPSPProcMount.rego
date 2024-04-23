package k8spspprocmount

included(resourceName, exclusions) = true {
  patterns := {pattern | exclusion := exclusions[_]; pattern := sprintf("^%v$", [exclusion])}
  resource := concat("/", [input.review.object.metadata.namespace, resourceName])
  matches := {match | match := patterns[_]; true == regex.match(match, resource)}
  count(matches) == 0
}

violation[{"msg": msg}] {
    c := input_containers[_]
    included(c.name, input.parameters.excludedResources)
    allowedProcMount := get_allowed_proc_mount(input)
    not input_proc_mount_type_allowed(allowedProcMount, c)
    msg := sprintf("ProcMount type is not allowed, container: %v. Allowed procMount types: %v", [c.name, allowedProcMount])
}

input_proc_mount_type_allowed(allowedProcMount, c) {
    allowedProcMount == "default"
    lower(c.securityContext.procMount) == "default"
}
input_proc_mount_type_allowed(allowedProcMount, c) {
    allowedProcMount == "unmasked"
}

input_containers[c] {
    c := input.review.object.spec.containers[_]
    c.securityContext.procMount
}
input_containers[c] {
    c := input.review.object.spec.initContainers[_]
    c.securityContext.procMount
}

get_allowed_proc_mount(arg) = out {
    not arg.parameters
    out = "default"
}
get_allowed_proc_mount(arg) = out {
    not arg.parameters.procMount
    out = "default"
}
get_allowed_proc_mount(arg) = out {
    not valid_proc_mount(arg.parameters.procMount)
    out = "default"
}
get_allowed_proc_mount(arg) = out {
    valid_proc_mount(arg.parameters.procMount)
    out = lower(arg.parameters.procMount)
}

valid_proc_mount(str) {
    lower(str) == "default"
}
valid_proc_mount(str) {
    lower(str) == "unmasked"
}
