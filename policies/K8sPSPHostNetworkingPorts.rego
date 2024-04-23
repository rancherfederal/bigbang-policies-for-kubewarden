package k8spsphostnetworkingports

included(resourceName, exclusions) = true {
  patterns := {pattern | exclusion := exclusions[_]; pattern := sprintf("^%v$", [exclusion])}
  resource := concat("/", [input.review.object.metadata.namespace, resourceName])
  matches := {match | match := patterns[_]; true == regex.match(match, resource)}
  count(matches) == 0
}

violation[{"msg": msg, "details": {}}] {
  input_share_hostnetwork(input.review.object)
  msg := sprintf("Sharing the hostNetwork is not allowed, pod: %v.", [input.review.object.metadata.name])
}

violation[{"msg": msg, "details": {}}] {
  container := input_containers[_]
  included(container.name, input.parameters.excludedResources)
  hostPort := container.ports[_].hostPort
  input_share_hostport(hostPort)
  msg := sprintf("The hostPort %v is not allowed in container %v.  Allowed: %v <= hostPort <= %v", [hostPort, container.name, input.parameters.min, input.parameters.max])
}

input_share_hostnetwork(o) {
  not input.parameters.hostNetwork
  included(o.metadata.name, input.parameters.excludedResources)
  o.spec.hostNetwork
}

input_share_hostport(hostPort) {
  hostPort < input.parameters.min
}

input_share_hostport(hostPort) {
  hostPort > input.parameters.max
}

input_containers[c] {
  c := input.review.object.spec.containers[_]
}

input_containers[c] {
  c := input.review.object.spec.initContainers[_]
}
