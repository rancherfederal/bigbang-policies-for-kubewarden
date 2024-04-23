package k8spspflexvolumes

included(resourceName, exclusions) = true {
  patterns := {pattern | exclusion := exclusions[_]; pattern := sprintf("^%v$", [exclusion])}
  resource := concat("/", [input.review.object.metadata.namespace, resourceName])
  matches := {match | match := patterns[_]; true == regex.match(match, resource)}
  count(matches) == 0
}

violation[{"msg": msg, "details": {}}] {
    included(input.review.object.metadata.name, input.parameters.excludedResources)
    volume := input_flexvolumes[_]
    not input_flexvolumes_allowed(volume)
    msg := sprintf("FlexVolume %v is not allowed, pod: %v. Allowed drivers: %v", [volume, input.review.object.metadata.name, input.parameters.allowedFlexVolumes])
}

input_flexvolumes_allowed(volume) {
    input.parameters.allowedFlexVolumes[_].driver == volume.flexVolume.driver
}

input_flexvolumes[v] {
    v := input.review.object.spec.volumes[_]
    has_field(v, "flexVolume")
}

# has_field returns whether an object has a field
has_field(object, field) = true {
    object[field]
}
