# regal ignore:directory-package-mismatch
package armo_builtins

import rego.v1

deny contains msg if {
	allowed := object.get(data.postureControlInputs, "imageRepositoryAllowList", [])
	count(allowed) > 0
	wl := input[_]
	ref := agent_registry_image_refs(wl)[_]
	not agent_registry_allowed(ref.image, allowed)
	msg := agent_registry_message(wl, ref.path)
}

agent_registry_image_refs(wl) := [ref | some i; some set in [{"name": "containers", "items": object.get(pod_spec, "containers", [])}, {"name": "initContainers", "items": object.get(pod_spec, "initContainers", [])}]; c := set.items[i]; ref := {"image": c.image, "path": sprintf("spec.podTemplate.spec.%s[%d].image", [set.name, i])}] if {
	wl.kind in {"Sandbox", "SandboxTemplate"}
	pod_spec := object.get(object.get(wl.spec, "podTemplate", {}), "spec", {})
}

agent_registry_image_refs(wl) := [{"image": wl.spec.workerImage, "path": "spec.workerImage"}] if wl.kind == "WorkerPool"

agent_registry_allowed(image, allowed) if {
	registry := allowed[_]
	startswith(image, concat("", [registry, "/"]))
}

agent_registry_allowed(image, allowed) if {
	"docker.io" in allowed
	parts := split(image, "/")
	count(parts) > 1
	first := parts[0]
	not contains(first, ".")
	not contains(first, ":")
	first != "localhost"
}

agent_registry_allowed(image, allowed) if {
	"docker.io" in allowed
	count(split(image, "/")) == 1
}

agent_registry_message(wl, path) := {"alertMessage": sprintf("%v image uses a registry outside imageRepositoryAllowList", [wl.kind]), "packagename": "armo_builtins", "failedPaths": [path], "reviewPaths": [path], "fixPaths": [], "alertScore": 8, "alertObject": {"k8sApiObjects": [wl]}}
