package armo_builtins

import future.keywords.in

# Filter only kinds that are in data.postureControlInputs.kindFilter.
# Filter out non-host-sensor as well.
# If no kindFilter - match every kind
deny[msg] {
	obj = input[_]
	obj.apiVersion == "hostdata.kubescape.cloud/v1beta0"
	filter_kind(obj.kind)
	msg := {"alertObject": {"externalObjects": obj}}
}

# Filter only kinds that are in data.postureControlInputs.kindFilter.
# If no kindFilter - match everything
filter_kind(kind) {
	kind in data.postureControlInputs.kindFilter
}

filter_kind(kind) {
	not data.postureControlInputs.kindFilter
}
