# regal ignore:directory-package-mismatch
package armo_builtins

import rego.v1

deny contains msg if {
	wl := input[_]
	pod_spec := object.get(object.get(wl.spec, "podTemplate", {}), "spec", {})
	container_sets := [{"name": "containers", "items": object.get(pod_spec, "containers", [])}, {"name": "initContainers", "items": object.get(pod_spec, "initContainers", [])}]
	container_set := container_sets[_]
	container := container_set.items[i]
	limits := object.get(object.get(container, "resources", {}), "limits", {})
	missing := [resource | resource := ["cpu", "memory"][_]; object.get(limits, resource, "") == ""]
	count(missing) > 0
	path := sprintf("spec.podTemplate.spec.%s[%d].resources.limits", [container_set.name, i])
	msg := agent_limit_message(wl, container, missing, path)
}

agent_limit_message(wl, container, missing, path) := {"alertMessage": sprintf("Container %q is missing %v limits", [container.name, missing]), "packagename": "armo_builtins", "failedPaths": [path], "fixPaths": [], "alertScore": 7, "alertObject": {"k8sApiObjects": [wl]}}
