package k8srequiredprobes

included(resourceName, exclusions) = true {
  patterns := {pattern | exclusion := exclusions[_]; pattern := sprintf("^%v$", [exclusion])}
  resource := concat("/", [input.review.object.metadata.namespace, resourceName])
  matches := {match | match := patterns[_]; true == regex.match(match, resource)}
  count(matches) == 0
}

violation[{"msg": msg}] {
  container := input.review.object.spec.containers[_]
  included(container.name, input.parameters.excludedResources)
  probe := input.parameters.probes[_]
  not container[probe]
  msg := sprintf("Container <%v> in your <%v> <%v> has no <%v>", [container.name, input.review.kind.kind, input.review.object.metadata.name, probe])
}

violation[{"msg": msg}] {
  container := input.review.object.spec.containers[_]
  included(container.name, input.parameters.excludedResources)
  probe := input.parameters.probes[_]
  container[probe]
  not check_probe_type(container, probe)
  probe_types := {type | type := input.parameters.probeTypes[_]}
  msg := sprintf("Probe <%v> in container <%v> in  <%v> <%v> has none of the required probetypes <%v>", [probe,container.name, input.review.kind.kind, input.review.object.metadata.name, probe_types])
}

check_probe_type(container, probe) = true {
   probe_types := {type | type := input.parameters.probeTypes[_]}
   container[probe][key]
   probe_types[key]
}