package armo_builtins

import data.cautils as cautils
import future.keywords.in


# Fail if etcd data dir not owned by etcd:etcd
deny[msg] {
	obj = input[_]
	obj.apiVersion == "hostdata.kubescape.cloud/v1beta0"
	obj.kind == "ControlPlaneInfo"

	# Test
	file := obj.etcdDataDir
	not valid_ownership(file.ownership)

	# Add name to match the externalObject structure
	output := json.patch(obj, [{"op": "add", "path": "name", "value": "ControlPlaneInfo"}])

	msg := {
		"alertMessage": sprintf("%s is not owned by `etcd:etcd`", [file.path]),
		"alertScore": 2,
		"failedPaths": [],
		"fixPaths": [],
		"fixCommand": sprintf("chown etcd:etcd %s", [file.path]),
		"packagename": "armo_builtins",
		"alertObject": {"externalObjects": output},
	}
}


valid_ownership(ownership) {
	ownership.err != "" # Don't fail if host-sensor can't get ownership
}
valid_ownership(ownership) {
	ownership.username == "etcd"
	ownership.groupname == "etcd"
}