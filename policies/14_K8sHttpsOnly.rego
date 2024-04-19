package k8shttpsonly2
included(resourceName, exclusions) = true {
  patterns := {pattern | exclusion := exclusions[_]; pattern := sprintf("^%v$", [exclusion])}
  resource := concat("/", [input.review.object.metadata.namespace, resourceName])
  matches := {match | match := patterns[_]; true == regex.match(match, resource)}
  count(matches) == 0
}
violation[{"msg": msg}] {
  input.review.object.kind == "Ingress"
  included(input.review.object.metadata.name, input.parameters.excludedResources)
