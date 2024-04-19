package k8squalityofservice

included(resourceName, exclusions) = true {
  patterns := {pattern | exclusion := exclusions[_]; pattern := sprintf("^%v$", [exclusion])}
  resource := concat("/", [input.review.object.metadata.namespace, resourceName])
  matches := {match | match := patterns[_]; true == regex.match(match, resource)}
  count(matches) == 0
}

# https://kubernetes.io/docs/tasks/configure-pod-container/quality-service-pod/#create-a-pod-that-gets-assigned-a-qos-class-of-guaranteed
violation[{"msg": msg, "details": {}}] {
  container := input_containers[_]
  included(container.name, input.parameters.excludedResources)
  container.resources.requests.memory = container.resources.limits.memory
  container.resources.requests.cpu = container.resources.limits.cpu
  msg = sprintf("%s in the %s %s does not have QoS class of Guaranteed", [container.name, input.kind, input.metadata.name])
}

input_containers[c] {
  c := input.review.object.spec.containers[_]
}
input_containers[c] {
  c := input.review.object.spec.initContainers[_]
}