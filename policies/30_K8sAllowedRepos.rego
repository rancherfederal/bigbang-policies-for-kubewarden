package k8sallowedrepos

included(resourceName, exclusions) = true {
  patterns := {pattern | exclusion := exclusions[_]; pattern := sprintf("^%v$", [exclusion])}
  resource := concat("/", [input.review.object.metadata.namespace, resourceName])
  matches := {match | match := patterns[_]; true == regex.match(match, resource)}
  count(matches) == 0
}

violation[{"msg": msg}] {
    container := input.review.object.spec.containers[_]
    included(container.name, input.parameters.excludedResources)
    satisfied := [good | repo = input.parameters.repos[_] ; good = startswith(container.image, repo)]
    not any(satisfied)
    msg := sprintf("container <%v> has an invalid repository for image <%v>, allowed repos are %v", [container.name, container.image, input.parameters.repos])
}

violation[{"msg": msg}] {
    container := input.review.object.spec.initContainers[_]
    included(container.name, input.parameters.excludedResources)
    satisfied := [good | repo = input.parameters.repos[_] ; good = startswith(container.image, repo)]
    not any(satisfied)
    msg := sprintf("container <%v> has an invalid repository for  image  <%v>, allowed repos are %v", [container.name, container.image, input.parameters.repos])
}