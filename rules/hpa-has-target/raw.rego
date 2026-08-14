# regal ignore:directory-package-mismatch
package armo_builtins

import rego.v1

deny contains msga if {
	hpa := input[_]
	hpa.kind == "HorizontalPodAutoscaler"
	scale_target_ref := object.get(hpa.spec, "scaleTargetRef", {})
	target_kind := object.get(scale_target_ref, "kind", "")
	known_scalable_kind(target_kind)
	namespace := object.get(hpa.metadata, "namespace", "default")
	target_name := object.get(scale_target_ref, "name", "")

	not target_exists(target_kind, target_name, namespace, input)

	msga := {
		"alertMessage": sprintf("HorizontalPodAutoscaler '%v' scaleTargetRef points to %v '%v' which does not exist in namespace '%v'", [hpa.metadata.name, target_kind, target_name, namespace]),
		"packagename": "armo_builtins",
		"failedPaths": ["spec.scaleTargetRef.name"],
		"fixPaths": [],
		"alertScore": 4,
		"alertObject": {"k8sApiObjects": [hpa]},
	}
}

# Only built-in scalable kinds are validated. A custom scalable resource
# (CRD implementing the scale subresource) cannot be resolved offline, so an
# unknown kind is skipped rather than falsely flagged.
known_scalable_kind(kind) if {
	kind in {"Deployment", "StatefulSet", "ReplicaSet", "ReplicationController"}
}

target_exists(kind, name, namespace, resources) if {
	wl := resources[_]
	wl.kind == kind
	wl_name := object.get(wl.metadata, "name", "")
	wl_name == name
	wl_namespace := object.get(wl.metadata, "namespace", "default")
	wl_namespace == namespace
}
