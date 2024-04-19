package k8sexternalips
included(resourceName, exclusions) = true {
  patterns := {pattern | exclusion := exclusions[_]; pattern := sprintf("^%v$", [exclusion])}
  resource := concat("/", [input.review.object.metadata.namespace, resourceName])
  matches := {match | match := patterns[_]; true == regex.match(match, resource)}
  count(matches) == 0
}
violation[{"msg": msg}] {
  input.review.kind.kind == "Service"
  input.review.kind.group == ""
  included(input.review.object.metadata.name, input.parameters.excludedResources)
  allowedIPs := {ip | ip := input.parameters.allowedIPs[_]}
  externalIPs := {ip | ip := input.review.object.spec.externalIPs[_]}
  forbiddenIPs := externalIPs - allowedIPs
  count(forbiddenIPs) > 0
  msg := sprintf("service has forbidden external IPs: %v", [forbiddenIPs])
}