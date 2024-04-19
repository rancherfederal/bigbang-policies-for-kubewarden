package k8sregulatedresources

violation[{"msg": msg}] {
  input.parameters.action == "allow"
  not count({input.review.object.metadata.name} & cast_set(input.parameters.resources)) == 1
  msg := sprintf("input resource  <%v> is not in the allowed list of resources <%v>", [input.review.object.metadata.name, input.parameters.resources])
}

violation[{"msg": msg}] {
  input.parameters.action == "deny"
  count({input.review.object.metadata.name} & cast_set(input.parameters.resources)) == 1
  msg := sprintf("input resource  <%v> is in the disallowed list of resources <%v>", [input.review.object.metadata.name, input.parameters.resources])
}
