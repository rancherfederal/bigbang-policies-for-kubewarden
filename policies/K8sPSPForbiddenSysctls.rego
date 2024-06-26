package k8spspforbiddensysctls

included(resourceName, exclusions) = true {
  patterns := {pattern | exclusion := exclusions[_]; pattern := sprintf("^%v$", [exclusion])}
  resource := concat("/", [input.review.object.metadata.namespace, resourceName])
  matches := {match | match := patterns[_]; true == regex.match(match, resource)}
  count(matches) == 0
}

violation[{"msg": msg, "details": {}}] {
    included(input.review.object.metadata.name, input.parameters.excludedResources)
    sysctl := input.review.object.spec.securityContext.sysctls[_].name
    forbidden_sysctl(sysctl)
    msg := sprintf("The sysctl %v is not allowed, pod: %v. Forbidden sysctls: %v", [sysctl, input.review.object.metadata.name, input.parameters.forbiddenSysctls])
}

# * may be used to forbid all sysctls
forbidden_sysctl(sysctl) {
    input.parameters.forbiddenSysctls[_] == "*"
}

forbidden_sysctl(sysctl) {
    input.parameters.forbiddenSysctls[_] == sysctl
}

forbidden_sysctl(sysctl) {
    startswith(sysctl, trim(input.parameters.forbiddenSysctls[_], "*"))
}
