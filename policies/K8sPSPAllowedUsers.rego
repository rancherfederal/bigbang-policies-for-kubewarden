package k8spspallowedusers

included(resourceName, exclusions) = true {
  patterns := {pattern | exclusion := exclusions[_]; pattern := sprintf("^%v$", [exclusion])}
  resource := concat("/", [input.review.object.metadata.namespace, resourceName])
  matches := {match | match := patterns[_]; true == regex.match(match, resource)}
  count(matches) == 0
}

violation[{"msg": msg}] {
  fields := ["runAsUser", "runAsGroup", "supplementalGroups", "fsGroup"]
  field := fields[_]
  container := input_containers[_]
  included(container.name, input.parameters.excludedResources)
  msg := get_type_violation(field, container)
}

get_type_violation(field, container) = msg {
  field == "runAsUser"
  params := input.parameters[field]
  msg := get_user_violation(params, container)
}

get_type_violation(field, container) = msg {
  field != "runAsUser"
  params := input.parameters[field]
  msg := get_violation(field, params, container)
}

# RunAsUser (separate due to "MustRunAsNonRoot")
get_user_violation(params, container) = msg {
  rule := params.rule
  provided_user := get_field_value("runAsUser", container, input.review)
  not accept_users(rule, provided_user)
  msg := sprintf("Container %v is attempting to run as disallowed user %v. Allowed runAsUser: %v", [container.name, provided_user, params])
}

get_user_violation(params, container) = msg {
  not get_field_value("runAsUser", container, input.review)
  params.rule = "MustRunAs"
  msg := sprintf("Container %v is attempting to run without a required securityContext/runAsUser", [container.name])
}

get_user_violation(params, container) = msg {
  params.rule = "MustRunAsNonRoot"
  not get_field_value("runAsUser", container, input.review)
  not get_field_value("runAsNonRoot", container, input.review)
  msg := sprintf("Container %v is attempting to run without a required securityContext/runAsNonRoot or securityContext/runAsUser != 0", [container.name])
}

accept_users("RunAsAny", provided_user) {true}

accept_users("MustRunAsNonRoot", provided_user) = res {res := provided_user != 0}

accept_users("MustRunAs", provided_user) = res  {
  ranges := input.parameters.runAsUser.ranges
  res := is_in_range(provided_user, ranges)
}

# Group Options
get_violation(field, params, container) = msg {
  rule := params.rule
  provided_value := get_field_value(field, container, input.review)
  not is_array(provided_value)
  not accept_value(rule, provided_value, params.ranges)
  msg := sprintf("Container %v is attempting to run as disallowed group %v. Allowed %v: %v", [container.name, provided_value, field, params])
}
# SupplementalGroups is array value
get_violation(field, params, container) = msg {
  rule := params.rule
  array_value := get_field_value(field, container, input.review)
  is_array(array_value)
  provided_value := array_value[_]
  not accept_value(rule, provided_value, params.ranges)
  msg := sprintf("Container %v is attempting to run with disallowed supplementalGroups %v. Allowed %v: %v", [container.name, array_value, field, params])
}

get_violation(field, params, container) = msg {
  not get_field_value(field, container, input.review)
  params.rule == "MustRunAs"
  msg := sprintf("Container %v is attempting to run without a required securityContext/%v. Allowed %v: %v", [container.name, field, field, params])
}

accept_value("RunAsAny", provided_value, ranges) {true}

accept_value("MayRunAs", provided_value, ranges) = res { res := is_in_range(provided_value, ranges)}

accept_value("MustRunAs", provided_value, ranges) = res { res := is_in_range(provided_value, ranges)}


# If container level is provided, that takes precedence
get_field_value(field, container, review) = out {
  container_value := get_seccontext_field(field, container)
  out := container_value
}

# If no container level exists, use pod level
get_field_value(field, container, review) = out {
  not has_seccontext_field(field, container)
  review.kind.kind == "Pod"
  pod_value := get_seccontext_field(field, review.object.spec)
  out := pod_value
}

# Helper Functions
is_in_range(val, ranges) = res {
  matching := {1 | val >= ranges[j].min; val <= ranges[j].max}
  res := count(matching) > 0
}

has_seccontext_field(field, obj) {
  get_seccontext_field(field, obj)
}

has_seccontext_field(field, obj) {
  get_seccontext_field(field, obj) == false
}

get_seccontext_field(field, obj) = out {
  out = obj.securityContext[field]
}

input_containers[c] {
  c := input.review.object.spec.containers[_]
}
input_containers[c] {
  c := input.review.object.spec.initContainers[_]
}
