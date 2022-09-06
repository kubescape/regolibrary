package armo_builtins

import data.cautils as cautils
import future.keywords.in

# Fail for every file in data.postureControlInputs.fileObjPath
# if the permissions of the file are more permissive that 600.
# Expect postureControlInputs.kindFilter and data.postureControlInputs.fileObjPath
deny[msg] {
	# Filter out irrelevent resources
	obj = input[_]
	obj.apiVersion == "hostdata.kubescape.cloud/v1beta0"
	filter_kind(obj.kind)

	# Get the file info using the input object-path
	subject := object.get(obj, data.postureControlInputs.fileObjPath, false)
	subject != false

	# Run the test for every file
	files := get_files(subject)
	file = files[_]

	# Actual permissions test    
	allowed_perms := 384 # 0o600 == 384
	not cautils.unix_permissions_allow(allowed_perms, file.permissions)

	alert := sprintf("the permissions of %s are too permissive. maximum allowed: %o. actual: %o", [file.path, allowed_perms, file.permissions])
	msg := {
		"alertMessage": alert,
		"alertScore": 2,
		"failedPaths": [],
		"fixPaths": [],
		"fixCommand": sprintf("chmod %o %s", [allowed_perms, file.path]),
		"packagename": "armo_builtins",
		"alertObject": {"externalObjects": obj},
	}
}

# Return always a list
get_files(obj) = files {
	is_array(obj)
	files = obj
}

get_files(obj) = files {
	not is_array(obj)
	files = [obj]
}

# Filter only kinds that are in data.postureControlInputs.kindFilter.
# If no kindFilter - match everything
filter_kind(kind) {
	kind in data.postureControlInputs.kindFilter
}

filter_kind(kind) {
	not data.postureControlInputs.kindFilter
}
