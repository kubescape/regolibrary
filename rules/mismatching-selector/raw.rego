package armo_builtins

import future.keywords.contains
import future.keywords.if
import future.keywords.in

deny contains msga if {
	wl := input[_]
	wl.kind in {"Deployment", "ReplicaSet", "DaemonSet", "StatefulSet"}
	selector := object.get(wl.spec.selector, "matchLabels", {})
	count(selector) > 0
	labels := object.get(wl.spec.template.metadata, "labels", {})
	selector_mismatch(selector, labels)

	msga := {
		"alertMessage": sprintf("%v: %v selector does not match pod template labels", [wl.kind, wl.metadata.name]),
		"packagename": "armo_builtins",
		"failedPaths": ["spec.selector.matchLabels"],
		"fixPaths": [],
		"alertScore": 3,
		"alertObject": {
			"k8sApiObjects": [wl],
		},
	}
}

selector_mismatch(selector, labels) if {
	selector[k]
	not labels[k] == selector[k]
}
