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

violation[{"msg": msg, "details": {"missing_labels": missing}}] {
  included(input.parameters.excludedResources)
  provided := {label | input.review.object.metadata.labels[label]}
  required := {label | label := input.parameters.labels[_].key}
  missing := required - provided
  count(missing) > 0
  def_msg := sprintf("you must provide labels: %v", [missing])
  msg := get_message(input.parameters, def_msg)
}

violation[{"msg": msg}] {
  included(input.parameters.excludedResources)
  value := input.review.object.metadata.labels[key]
  expected := input.parameters.labels[_]
  expected.key == key
  # do not match if allowedRegex is not defined, or is an empty string
  expected.allowedRegex != ""
  not re_match(expected.allowedRegex, value)
  def_msg := sprintf("Label <%v: %v> does not satisfy allowed regex: %v", [key, value, expected.allowedRegex])
  msg := get_message(input.parameters, def_msg)
}
