
package k8sprotectednamespaces

violation[{"msg": msg}] {
  not input.review.object.metadata.namespace
  msg := "Default Namespace is protected. Please specify an alternate valid namespace"
}
violation[{"msg": msg}] {
  count({input.review.object.metadata.namespace} & cast_set(input.parameters.resources)) == 1
  msg := sprintf("namespace <%v> is protected. This is the list of protected namespaces <%v>", [input.review.object.metadata.namespace, input.parameters.resources])
}
