# regal ignore:directory-package-mismatch
package armo_builtins

import rego.v1

deny contains msg if {
	wl := input[_]
	allowed := object.get(data.postureControlInputs, "imageRepositoryAllowList", [])
	count(allowed) > 0
	ref := agent_registry_image_refs(wl)[_]
	not agent_registry_allowed(ref.image, allowed)
	msg := agent_registry_message(wl, ref.path)
}

agent_registry_image_refs(wl) := [ref | some i; some set in [{"name": "containers", "items": object.get(pod_spec, "containers", [])}, {"name": "initContainers", "items": object.get(pod_spec, "initContainers", [])}]; c := set.items[i]; ref := {"image": c.image, "path": sprintf("spec.podTemplate.spec.%s[%d].image", [set.name, i])}] if {
	wl.kind in {"Sandbox", "SandboxTemplate"}
	pod_spec := object.get(object.get(wl.spec, "podTemplate", {}), "spec", {})
}

agent_registry_image_refs(wl) := [{"image": wl.spec.ateomImage, "path": "spec.ateomImage"}] if wl.kind == "WorkerPool"

agent_registry_image_refs(wl) := array.concat([{"image": wl.spec.pauseImage, "path": "spec.pauseImage"}], container_refs) if {
	wl.kind == "ActorTemplate"
	container_refs := [ref | c := object.get(wl.spec, "containers", [])[i]; ref := {"image": c.image, "path": sprintf("spec.containers[%d].image", [i])}]
}

agent_registry_allowed(image, allowed) if {
	registry := allowed[_]
	startswith(image, concat("", [registry, "/"]))
}

agent_registry_allowed(image, allowed) if {
	"docker.io" in allowed
	first := split(image, "/")[0]
	not contains(first, ".")
	not contains(first, ":")
	first != "localhost"
}

agent_registry_message(wl, path) := {"alertMessage": sprintf("%v image uses a registry outside imageRepositoryAllowList", [wl.kind]), "packagename": "armo_builtins", "failedPaths": [path], "fixPaths": [], "alertScore": 8, "alertObject": {"k8sApiObjects": [wl]}}
