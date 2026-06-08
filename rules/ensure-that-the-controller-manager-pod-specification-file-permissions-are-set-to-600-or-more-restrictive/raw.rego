# regal ignore:directory-package-mismatch
package armo_builtins

import data.cautils
import rego.v1

deny contains msg if {
	file_obj_path := ["data", "controllerManagerInfo", "specsFile"]
	allowed_perms := 384 # == 0o600

	# Filter out irrelevent resources
	some obj in input
	is_control_plane_info(obj)

	file := object.get(obj, file_obj_path, false)

	# Actual permissions test
	not cautils.unix_permissions_allow(allowed_perms, file.permissions)

	# Build the message
	# filter out irrelevant host-sensor data
	obj_filtered := json.filter(obj, [
		concat("/", file_obj_path),
		"apiVersion",
		"kind",
		"metadata",
	])

	alert := sprintf("the permissions of %s are too permissive. maximum allowed: %o. actual: %o", [file.path, allowed_perms, file.permissions])
	msg := {
		"alertMessage": alert,
		"alertScore": 2,
		"failedPaths": [],
		"fixPaths": [],
		"fixCommand": sprintf("chmod %o %s", [allowed_perms, file.path]),
		"packagename": "armo_builtins",
		"alertObject": {"externalObjects": obj_filtered},
	}
}

is_control_plane_info(obj) if {
	obj.apiVersion == "hostdata.kubescape.cloud/v1beta0"
	obj.kind == "ControlPlaneInfo"
}
