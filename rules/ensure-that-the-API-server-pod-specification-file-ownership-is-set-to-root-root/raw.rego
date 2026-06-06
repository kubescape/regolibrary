# regal ignore:directory-package-mismatch
package armo_builtins

import data.cautils
import rego.v1

deny contains msg if {
	allowed_user := "root"
	allowed_group := "root"
	file_obj_path := ["data", "APIServerInfo", "specsFile"]


	# Filter out irrelevent resources
	some obj in input
	is_control_plane_info(obj)

	file := object.get(obj, file_obj_path, false)

	# Actual ownership check
	not allowed_ownership(file.ownership, allowed_user, allowed_group)

	# Build the message
	# filter out irrelevant host-sensor data
	obj_filtered := json.filter(obj, [
		concat("/", file_obj_path),
		"apiVersion",
		"kind",
		"metadata",
	])

	alert := sprintf("%s is not owned by %s:%s (actual owners are %s:%s)", [
		file.path,
		allowed_user,
		allowed_group,
		file.ownership.username,
		file.ownership.groupname,
	])

	msg := {
		"alertMessage": alert,
		"alertScore": 2,
		"failedPaths": [],
		"fixPaths": [],
		"fixCommand": sprintf("chown %s:%s %s", [allowed_user, allowed_group, file.path]),
		"packagename": "armo_builtins",
		"alertObject": {"externalObjects": obj_filtered},
	}
}

is_control_plane_info(obj) if {
	obj.apiVersion == "hostdata.kubescape.cloud/v1beta0"
	obj.kind == "ControlPlaneInfo"
}

allowed_ownership(ownership, user, group) if {
	ownership.error # Do not fail if ownership is not found
}

allowed_ownership(ownership, user, group) if {
	ownership.username == user
	ownership.groupname == group
}
