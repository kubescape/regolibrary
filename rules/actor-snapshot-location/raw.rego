# regal ignore:directory-package-mismatch
package armo_builtins

import rego.v1

deny contains msg if {
	wl := input[_]
	allowed := object.get(data.postureControlInputs, "agentSnapshotLocationAllowList", [])
	count(allowed) > 0
	location := object.get(object.get(wl.spec, "snapshotsConfig", {}), "location", "")
	not actor_snapshot_prefix_allowed(location, allowed)
	msg := {"alertMessage": "ActorTemplate snapshot location is outside agentSnapshotLocationAllowList; this check does not verify encryption", "packagename": "armo_builtins", "failedPaths": ["spec.snapshotsConfig.location"], "fixPaths": [], "alertScore": 6, "alertObject": {"k8sApiObjects": [wl]}}
}

actor_snapshot_prefix_allowed(location, allowed) if {
	prefix := allowed[_]
	startswith(location, prefix)
}
