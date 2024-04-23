package k8spspapparmor

included(resourceName, exclusions) = true {
  patterns := {pattern | exclusion := exclusions[_]; pattern := sprintf("^%v$", [exclusion])}
  resource := concat("/", [input.review.object.metadata.namespace, resourceName])
  matches := {match | match := patterns[_]; true == regex.match(match, resource)}
  count(matches) == 0
}

violation[{"msg": msg, "details": {}}] {
    metadata := input.review.object.metadata
    container := input_containers[_]
    included(container.name, input.parameters.excludedResources)
    not input_apparmor_allowed(container, metadata)
    msg := sprintf("AppArmor profile is not allowed, pod: %v, container: %v. Allowed profiles: %v", [input.review.object.metadata.name, container.name, input.parameters.allowedProfiles])
}

input_apparmor_allowed(container, metadata) {
    metadata.annotations[key] == input.parameters.allowedProfiles[_]
    key == sprintf("container.apparmor.security.beta.kubernetes.io/%v", [container.name])
}

input_containers[c] {
    c := input.review.object.spec.containers[_]
}
input_containers[c] {
    c := input.review.object.spec.initContainers[_]
}
