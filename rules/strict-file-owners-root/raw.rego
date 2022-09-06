package armo_builtins

import data.cautils as cautils
import future.keywords.in

# Fail for every file in data.postureControlInputs.fileObjPath
# if the owners of the file are not `root:root`.
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
	cautils.is_not_strict_conf_ownership(file.ownership)

	msg := {
		"alertMessage": sprintf("%s is not owned by `root:root`", [file.path]),
		"alertScore": 2,
		"failedPaths": [],
		"fixPaths": [],
		"fixCommand": sprintf("chown root:root %s", [file.path]),
		"packagename": "armo_builtins",
		"alertObject": {"externalObjects": obj},
	}
}

# Always return a list
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
