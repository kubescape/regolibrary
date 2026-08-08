# regal ignore:directory-package-mismatch
package armo_builtins

import rego.v1

deny contains msg if {
	wl := input[_]
	image_ref := agent_digest_image_refs(wl)[_]
	not regex.match(`^.+@sha256:[A-Fa-f0-9]{64}$`, image_ref.image)
	msg := agent_digest_message(wl, image_ref.path)
}

agent_digest_image_refs(wl) := [ref | some i; some set in [{"name": "containers", "items": object.get(pod_spec, "containers", [])}, {"name": "initContainers", "items": object.get(pod_spec, "initContainers", [])}]; c := set.items[i]; ref := {"image": c.image, "path": sprintf("spec.podTemplate.spec.%s[%d].image", [set.name, i])}] if {
	wl.kind in {"Sandbox", "SandboxTemplate"}
	pod_spec := object.get(object.get(wl.spec, "podTemplate", {}), "spec", {})
}

agent_digest_image_refs(wl) := [{"image": wl.spec.ateomImage, "path": "spec.ateomImage"}] if wl.kind == "WorkerPool"

agent_digest_image_refs(wl) := array.concat([{"image": wl.spec.pauseImage, "path": "spec.pauseImage"}], container_refs) if {
	wl.kind == "ActorTemplate"
	container_refs := [ref | c := object.get(wl.spec, "containers", [])[i]; ref := {"image": c.image, "path": sprintf("spec.containers[%d].image", [i])}]
}

agent_digest_message(wl, path) := {"alertMessage": sprintf("%v image must be pinned to an exact SHA-256 digest", [wl.kind]), "packagename": "armo_builtins", "failedPaths": [path], "fixPaths": [], "alertScore": 8, "alertObject": {"k8sApiObjects": [wl]}}
