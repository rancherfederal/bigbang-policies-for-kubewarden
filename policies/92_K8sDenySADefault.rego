package  k8sdenysadefault
default_sa(obj) = true {
  not obj.serviceAccount
}
default_sa(obj) = true {
  obj.serviceAccount == "default"
}
included(resourceName, exclusions) = true {
  patterns := {pattern | exclusion := exclusions[_]; pattern := sprintf("^%v$", [exclusion])}
  resource := concat("/", [input.review.object.metadata.namespace, resourceName])
  matches := {match | match := patterns[_]; true == regex.match(match, resource)}
  count(matches) == 0
}
violation[{"msg": msg, "details": {}}] {
  p := input_pod[_]
  included(p.metadata.name, input.parameters.excludedResources)
  default_sa(p.spec)
  msg := sprintf("Default Service Account is not allowed for pod %s in namespace %s",  [p.metadata.name,p.metadata.namespace])
}
input_pod[p] {
  p := input.review.object
}