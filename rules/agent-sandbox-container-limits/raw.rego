# regal ignore:directory-package-mismatch
package armo_builtins

import rego.v1

deny contains msg if {
	wl := input[_]
	wl.kind in {"Sandbox", "SandboxTemplate"}
	pod_spec := object.get(object.get(wl.spec, "podTemplate", {}), "spec", {})
	container_sets := [{"name": "containers", "items": object.get(pod_spec, "containers", [])}, {"name": "initContainers", "items": object.get(pod_spec, "initContainers", [])}]
	container_set := container_sets[_]
	container := container_set.items[i]
	missing := [resource | resource := ["cpu", "memory"][_]; object.get(container, ["resources", "limits", resource], "") == ""]
	count(missing) > 0
	container_path := sprintf("spec.podTemplate.spec.%s[%d]", [container_set.name, i])
	path := sprintf("%s.resources.limits", [container_path])
	fix_paths := [{"path": sprintf("%s.%s", [path, resource]), "value": "YOUR_VALUE"} | resource := missing[_]]
	msg := agent_limit_message(wl, container, missing, path, limits_review_path(container, container_path), fix_paths)
}

agent_limit_message(wl, container, missing, path, review_path, fix_paths) := {"alertMessage": sprintf("Container %q is missing %v limits", [container.name, missing]), "packagename": "armo_builtins", "failedPaths": [path], "reviewPaths": [review_path], "fixPaths": fix_paths, "alertScore": 7, "alertObject": {"k8sApiObjects": [wl]}}

# The deepest of resources.limits, resources and the container itself that the
# container has, so the evidence points at a field that is there.
limits_review_path(container, container_path) := sprintf("%s.resources.limits", [container_path]) if {
	is_object(container.resources.limits)
} else := sprintf("%s.resources", [container_path]) if {
	is_object(container.resources)
} else := container_path
