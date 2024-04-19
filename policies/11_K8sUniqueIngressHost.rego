package k8suniqueingresshost

included(resourceName, exclusions) = true {
  patterns := {pattern | exclusion := exclusions[_]; pattern := sprintf("^%v$", [exclusion])}
  resource := concat("/", [input.review.object.metadata.namespace, resourceName])
  matches := {match | match := patterns[_]; true == regex.match(match, resource)}
  count(matches) == 0
}
identical(obj, review) {
  obj.metadata.namespace == review.object.metadata.namespace
  obj.metadata.name == review.object.metadata.name
}
violation[{"msg": msg}] {
  input.review.kind.kind == "Ingress"
  included(input.review.object.metadata.name, input.parameters.excludedResources)
  re_match("^(extensions|networking.k8s.io)$", input.review.kind.group)
  host := input.review.object.spec.rules[_].host
  other := data.inventory.namespace[ns][otherapiversion]["Ingress"][name]
  re_match("^(extensions|networking.k8s.io)/.+$", otherapiversion)
  other.spec.rules[_].host == host
  not identical(other, input.review)
  msg := sprintf("ingress host conflicts with an existing ingress <%v>", [host])
}