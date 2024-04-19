       package k8sblocknodeport
included(resourceName, exclusions) = true {
  patterns := {pattern | exclusion := exclusions[_]; pattern := sprintf("^%v$", [exclusion])}
  resource := concat("/", [input.review.object.metadata.namespace, resourceName])
  matches := {match | match := patterns[_]; true == regex.match(match, resource)}
  count(matches) == 0
}
violation[{"msg": msg}] {
  input.review.kind.kind == "Service"
  input.review.object.spec.type == "NodePort"
  included(input.review.object.metadata.name, input.parameters.excludedResources)
  msg := sprintf("Service type can't be NodePort for the service %v",  [input.review.object.metadata.name])
}