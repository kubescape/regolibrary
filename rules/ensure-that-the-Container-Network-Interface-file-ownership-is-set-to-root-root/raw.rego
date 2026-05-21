package armo_builtins

import rego.v1

import data.cautils

deny contains msg if {
	# Filter out irrelevent resources
	obj = input[_]
	is_CNIInfo(obj)

	file_obj_path := ["data", "CNIConfigFiles"]
	files := object.get(obj, file_obj_path, false)
	file := files[file_index]

	# Actual ownership check
	allowed_user := "root"
	allowed_group := "root"
	not allowed_ownership(file.ownership, allowed_user, allowed_group)

	# Build the message
	# filter out irrelevant host-sensor data
	obj_filtered := json.filter(obj, [
		sprintf("%s/%d", [concat("/", file_obj_path), file_index]), "apiVersion",
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

is_CNIInfo(obj) if {
	obj.apiVersion == "hostdata.kubescape.cloud/v1beta0"
	obj.kind == "CNIInfo"
}

allowed_ownership(ownership, user, group) if {
	ownership.error # Do not fail if ownership is not found
}

allowed_ownership(ownership, user, group) if {
	ownership.username == user
	ownership.groupname == group
}
