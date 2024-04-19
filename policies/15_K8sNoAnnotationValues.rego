# Label expected on namespace
package k8srequiredlabels

resource = concat("/", [input.review.object.metadata.namespace, input.review.object.metadata.name]) {
  input.review.object.metadata.namespace
} else = input.review.object.metadata.name

included(exclusions) = true {
  patterns := {pattern | exclusion := exclusions[_]; pattern := sprintf("^%v$", [exclusion])}
  matches := {match | match := patterns[_]; true == regex.match(match, resource)}
  count(matches) == 0
}

get_message(parameters, _default) = msg {
  not parameters.message
  msg := _default
}

get_message(parameters, _default) = msg {
  msg := parameters.message
}

violation[{"msg": msg}] {
  included(input.parameters.excludedResources)
  value := input.review.object.metadata.annotations[key]
  expected := input.parameters.annotations[_]
  expected.key == key
  # do not match if disallowedRegex is not defined, or is an empty string
  expected.disallowedRegex != ""
  re_match(expected.disallowedRegex, value)
  def_msg := sprintf("Annotation <%v: %v> matches disallowed regex: %v", [key, value, expected.disallowedRegex])
  msg := get_message(input.parameters, def_msg)
}