package k8sbannedimagetags

included(resourceName, exclusions) = true {
  patterns := {pattern | exclusion := exclusions[_]; pattern := sprintf("^%v$", [exclusion])}
  resource := concat("/", [input.review.object.metadata.namespace, resourceName])
  matches := {match | match := patterns[_]; true == regex.match(match, resource)}
  count(matches) == 0
}

violation[{"msg": msg}] {
  container := input.review.object.spec.containers[_]
  included(container.name, input.parameters.excludedResources)
  img_split := split(container.image, ":")
  tag := img_split[count(img_split) - 1]
  banned := {s | s = input.parameters.tags[_]}
  banned[tag]
  msg := sprintf("container <%v> has banned image tag <%v>, banned tags are %v", [container.name, tag, banned])
}

violation[{"msg": msg}] {
  container := input.review.object.spec.containers[_]
  included(container.name, input.parameters.excludedResources)
  tag := [contains(container.image, ":")]
  not all(tag)
  msg := sprintf("container <%v> didn't specify an image tag <%v>", [container.name, container.image])
}