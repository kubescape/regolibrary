package armo_builtins

import future.keywords.in

import data.cautils

deny[msg] {
	# Filter out irrelevent resources
	obj = input[_]
	is_control_plane_info(obj)

	file_obj_path := ["data", "PKIFiles"]
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

deny[msg] {
	# Filter out irrelevent resources
	obj = input[_]
	is_control_plane_info(obj)

	file_obj_path := ["data", "PKIDir"]
	file := object.get(obj, file_obj_path, false)

	# Actual ownership check
	allowed_user := "root"
	allowed_group := "root"
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

is_control_plane_info(obj) {
	obj.apiVersion == "hostdata.kubescape.cloud/v1beta0"
	obj.kind == "ControlPlaneInfo"
}

allowed_ownership(ownership, user, group) {
	ownership.error # Do not fail if ownership is not found
}

allowed_ownership(ownership, user, group) {
	ownership.username == user
	ownership.groupname == group
}
