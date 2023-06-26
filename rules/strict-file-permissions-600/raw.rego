package armo_builtins

import future.keywords.in

import data.cautils

# Fail for every file in data.postureControlInputs.fileObjPath
# if the permissions of the file are more permissive that 600.
# Expect (supposed to be fixed per control, not user configurable):
# 	(required) data.postureControlInputs.fileObjPath - list of paths strings. The item delimiter is `.`.
# 	(optional) data.postureControlInputs.kindFilter
# 	(optional) data.postureControlInputs.pathGlob
deny[msg] {
	# Filter out irrelevent resources
	obj = input[_]
	obj.apiVersion == "hostdata.kubescape.cloud/v1beta0"
	filter_kind(obj.kind)

	# Get the file info using the input object-paths
	rawObjPath = data.postureControlInputs.fileObjPath[_]
	objPath := split(rawObjPath, "/")
	subject := object.get(obj, objPath, false)
	subject != false

	# Run the test for every file
	files := get_files(subject)
	file = files[file_index]
	file_path_glob(file.path)

	# Actual permissions test
	allowed_perms := 384 # 0o600 == 384
	not cautils.unix_permissions_allow(allowed_perms, file.permissions)

	# Filter out irrelevant data from the alert object
	file_filtered := filter_file(obj, objPath, file_index)
	obj_filtered := json.filter(obj, ["apiVersion", "kind", "metadata"])
	output := object.union(file_filtered, obj_filtered)

	alert := sprintf("the permissions of %s are too permissive. maximum allowed: %o. actual: %o", [file.path, allowed_perms, file.permissions])
	msg := {
		"alertMessage": alert,
		"alertScore": 2,
		"failedPaths": [],
		"fixPaths": [],
		"fixCommand": sprintf("chmod %o %s", [allowed_perms, file.path]),
		"packagename": "armo_builtins",
		"alertObject": {"externalObjects": output},
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

# Filter file path globs from data.postureControlInputs.pathGlob
file_path_glob(path) {
	patterns = data.postureControlInputs.pathGlob
	count({true | patterns[i]; glob.match(patterns[i], null, path)}) > 0
}

file_path_glob(path) {
	not data.postureControlInputs.pathGlob
}

# Filter only the current file
filter_file(obj, objPath, file_index) = ret {
	is_array(object.get(obj, objPath, false))
	full_path := array.concat(objPath, [format_int(file_index, 10)])
	final_path := concat("/", full_path)
	ret := json.filter(obj, [final_path])
}

filter_file(obj, objPath, file_index) = ret {
	not is_array(object.get(obj, objPath, false))
	ret = object.filter(obj, objPath)
}