# regal ignore:directory-package-mismatch 
package armo_builtins

import data.cautils
import rego.v1

deny contains msg if {
	file_obj_path := ["data", "serviceFiles"]
    allowed_user := "root"
	allowed_group := "root"
	
	# Filter out irrelevent resources
	some obj in input
	is_kubelet_info(obj)

	files := object.get(obj, file_obj_path, false)
	file := files[file_index]

	# Actual ownership check
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

is_kubelet_info(obj) if {
	obj.apiVersion == "hostdata.kubescape.cloud/v1beta0"
	obj.kind == "KubeletInfo"
}

allowed_ownership(ownership, user, group) if {
	ownership.error # Do not fail if ownership is not found
}

allowed_ownership(ownership, user, group) if {
	ownership.username == user
	ownership.groupname == group
}
