package armo_builtins

import data.cautils as cautils
import future.keywords.in

# Fail for every file in data.postureControlInputs.fileObjPath
# if the owners of the file are not `root:root`.
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

	# Actual ownership test    
	cautils.is_not_strict_conf_ownership(file.ownership)

	# Filter out irrelevant data from the alert object
	file_filtered := filter_file(obj, objPath, file_index)
	obj_filtered := json.filter(obj, ["apiVersion", "kind", "metadata"])
	output := object.union(file_filtered, obj_filtered)

	msg := {
		"alertMessage": sprintf("%s is not owned by `root:root`", [file.path]),
		"alertScore": 2,
		"failedPaths": [],
		"fixPaths": [],
		"fixCommand": sprintf("chown root:root %s", [file.path]),
		"packagename": "armo_builtins",
		"alertObject": {"externalObjects": output},
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
