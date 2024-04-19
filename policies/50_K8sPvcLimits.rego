package k8spvclimits

missing(obj, field) = true {
  not obj[field]
}

missing(obj, field) = true {
  obj[field] == ""
}

# 10 ** 21
mem_multiple("E") = 1000000000000000000000 { true }

# 10 ** 18
mem_multiple("P") = 1000000000000000000 { true }

# 10 ** 15
mem_multiple("T") = 1000000000000000 { true }

# 10 ** 12
mem_multiple("G") = 1000000000000 { true }

# 10 ** 9
mem_multiple("M") = 1000000000 { true }

# 10 ** 6
mem_multiple("K") = 1000000 { true }

# 10 ** 3
mem_multiple("") = 1000 { true }

# Kubernetes accepts millibyte precision when it probably shouldn't.
# https://github.com/kubernetes/kubernetes/issues/28741
# 10 ** 0
mem_multiple("m") = 1 { true }

# 1000 * 2 ** 10
mem_multiple("Ki") = 1024000 { true }

# 1000 * 2 ** 20
mem_multiple("Mi") = 1048576000 { true }

# 1000 * 2 ** 30
mem_multiple("Gi") = 1073741824000 { true }

# 1000 * 2 ** 40
mem_multiple("Ti") = 1099511627776000 { true }

# 1000 * 2 ** 50
mem_multiple("Pi") = 1125899906842624000 { true }

# 1000 * 2 ** 60
mem_multiple("Ei") = 1152921504606846976000 { true }

get_suffix(mem) = suffix {
  not is_string(mem)
  suffix := ""
}

get_suffix(mem) = suffix {
  is_string(mem)
  count(mem) > 0
  suffix := substring(mem, count(mem) - 1, -1)
  mem_multiple(suffix)
}

get_suffix(mem) = suffix {
  is_string(mem)
  count(mem) > 1
  suffix := substring(mem, count(mem) - 2, -1)
  mem_multiple(suffix)
}

get_suffix(mem) = suffix {
  is_string(mem)
  count(mem) > 1
  not mem_multiple(substring(mem, count(mem) - 1, -1))
  not mem_multiple(substring(mem, count(mem) - 2, -1))
  suffix := ""
}

get_suffix(mem) = suffix {
  is_string(mem)
  count(mem) == 1
  not mem_multiple(substring(mem, count(mem) - 1, -1))
  suffix := ""
}

get_suffix(mem) = suffix {
  is_string(mem)
  count(mem) == 0
  suffix := ""
}

canonify_mem(orig) = new {
  is_number(orig)
  new := orig * 1000
}

canonify_mem(orig) = new {
  not is_number(orig)
  suffix := get_suffix(orig)
  raw := replace(orig, suffix, "")
  re_match("^[0-9]+$", raw)
  new := to_number(raw) * mem_multiple(suffix)
}

included(resourceName, exclusions) = true {
  patterns := {pattern | exclusion := exclusions[_]; pattern := sprintf("^%v$", [exclusion])}
  resource := concat("/", [input.review.object.metadata.namespace, resourceName])
  matches := {match | match := patterns[_]; true == regex.match(match, resource)}
  count(matches) == 0
}

violation[{"msg": msg}] {
  included(input.review.object.metadata.name, input.parameters.excludedResources)
  storage_orig := input.review.object.spec.resources.requests.storage
  not canonify_mem(storage_orig)
  msg := sprintf("PVC <%v> storagelimit <%v> could not be parsed", [input.review.object.metadata.name, storage_orig])
}

violation[{"msg": msg}] {
  included(input.review.object.metadata.name, input.parameters.excludedResources)
  not input.review.object.spec.resources
  msg := sprintf("PVC <%v> has no resource requests", [input.review.object.metadata.name])
}

violation[{"msg": msg}] {
  included(input.review.object.metadata.name, input.parameters.excludedResources)
  not input.review.object.spec.resources.requests
  msg := sprintf("PVC <%v> has no resource requests", [input.review.object.metadata.name])
}

violation[{"msg": msg}] {
  included(input.review.object.metadata.name, input.parameters.excludedResources)
  not input.review.object.spec.resources.requests.storage
  msg := sprintf("PVC <%v> has no resource requests", [input.review.object.metadata.name])
}


violation[{"msg": msg}] {
  included(input.review.object.metadata.name, input.parameters.excludedResources)
  storage_orig := input.review.object.spec.resources.requests.storage
  storage := canonify_mem(storage_orig)
  max_storage_orig := input.parameters.storage
  max_storage := canonify_mem(max_storage_orig)
  storage > max_storage
  msg := sprintf("PVC <%v> storage limit <%v> is higher than the maximum allowed of <%v>", [input.review.object.metadata.name, storage_orig, max_storage_orig])
}

