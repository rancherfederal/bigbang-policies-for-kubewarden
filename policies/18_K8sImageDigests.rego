package k8simagedigests2

included(resourceName, exclusions) = true {
  patterns := {pattern | exclusion := exclusions[_]; pattern := sprintf("^%v$", [exclusion])}
  resource := concat("/", [input.review.object.metadata.namespace, resourceName])
  matches := {match | match := patterns[_]; true == regex.match(match, resource)}
  count(matches) == 0
}

violation[{"msg": msg}] {
  container := input.review.object.spec.containers[_]
  included(container.name, input.parameters.excludedResources)
  satisfied := [re_match("@[a-z0-9]+([+._-][a-z0-9]+)*:[a-zA-Z0-9=_-]+", container.image)]
  not all(satisfied)
  msg := sprintf("container <%v> uses an image without a digest <%v>", [container.name, container.image])
}
violation[{"msg": msg}] {
  container := input.review.object.spec.initContainers[_]
  included(container.name, input.parameters.excludedResources)
  satisfied := [re_match("@[a-z0-9]+([+._-][a-z0-9]+)*:[a-zA-Z0-9=_-]+", container.image)]
  not all(satisfied)
  msg := sprintf("initContainer <%v> uses an image without a digest <%v>", [container.name, container.image])
}