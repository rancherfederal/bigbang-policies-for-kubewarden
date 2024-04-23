package k8sallowedrepos

import data.k8sallowedrepos.violation

included(resourceName, exclusions) {
	patterns := {pattern | exclusion := exclusions[_]; pattern := sprintf("^%v$", [exclusion])}
	resource := concat("/", [input.review.object.metadata.namespace, resourceName])
	matches := {match | match := patterns[_]; true == regex.match(match, resource)}
	count(matches) == 0
}
