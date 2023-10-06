package armo_builtins

# CIS 4.2.10 https://workbench.cisecurity.org/sections/1126668/recommendations/1838657

deny[msga] {
	obj := input[_]
	is_kubelet_info(obj)

	command := obj.data.cmdLine

	not contains(command, "--config")

	res := not_set_arguments(command)
	count(res) != 0

	failed_args := extract_failed_object(res, "cliArg")

	external_obj := json.filter(obj, ["apiVersion", "data/cmdLine", "kind", "metadata"])

	msga := {
		"alertMessage": sprintf("%v should be set", [failed_args]),
		"alertScore": 2,
		"fixPaths": [],
		"failedPaths": [],
		"packagename": "armo_builtins",
		"alertObject": {"externalObjects": external_obj},
	}
}

deny[msga] {
	obj := input[_]
	is_kubelet_info(obj)

	command := obj.data.cmdLine

	contains(command, "--config")

	res := not_set_arguments(command)
	count(res) == 2

	decodedConfigContent := base64.decode(obj.data.configFile.content)
	yamlConfig := yaml.unmarshal(decodedConfigContent)

	propsResult := not_set_props(yamlConfig)
	count(propsResult) != 0

	failed_props := extract_failed_object(propsResult, "configProp")

	msga := {
		"alertMessage": sprintf("%v must be set", [failed_props]),
		"alertScore": 2,
		"failedPaths": [],
		"fixPaths": [],
		"packagename": "armo_builtins",
		"alertObject": {"externalObjects": {
			"apiVersion": obj.apiVersion,
			"kind": obj.kind,
			"metadata": obj.metadata,
			"data": {"configFile": {"content": decodedConfigContent}},
		}},
	}
}

deny[msga] {
	obj := input[_]
	is_kubelet_info(obj)

	command := obj.data.cmdLine

	contains(command, "--config")

	# only 1 argument is set via cli
	res := not_set_arguments(command)
	count(res) == 1

	# get yaml config equivalent
	not_set_prop := res[0].configProp

	failed_args := extract_failed_object(res, "cliArg")

	decodedConfigContent := base64.decode(obj.data.configFile.content)
	yamlConfig := yaml.unmarshal(decodedConfigContent)

	not yamlConfig[not_set_prop]

	msga := {
		"alertMessage": sprintf("%v should be set", [failed_args]),
		"alertScore": 2,
		"failedPaths": [],
		"fixPaths": [],
		"packagename": "armo_builtins",
		"alertObject": {"externalObjects": {
			"apiVersion": obj.apiVersion,
			"kind": obj.kind,
			"metadata": obj.metadata,
			"data": {"configFile": {"content": decodedConfigContent}},
		}},
	}
}

extract_failed_object(resultList, keyField) = failed_objects {
	failed_objects_array = [mapped |
		singleResult := resultList[_]
		mapped := singleResult[keyField]
	]

	failed_objects = concat(", ", failed_objects_array)
}

not_set_arguments(cmd) = result {
	wanted = [
		["--tls-cert-file", "tlsCertFile"],
		["--tls-private-key-file", "tlsPrivateKeyFile"],
	]

	result = [{
		"cliArg": wanted[i][0],
		"configProp": wanted[i][1],
	} |
		not contains(cmd, wanted[i][0])
	]
}

not_set_props(yamlConfig) = result {
	wanted = [
		["tlsCertFile", "--tls-cert-file"],
		["tlsPrivateKeyFile", "--tls-private-key-file"],
	]

	result = [{
		"cliArg": wanted[i][1],
		"configProp": wanted[i][0],
	} |
		not yamlConfig[wanted[i][0]]
	]
}

is_kubelet_info(obj) {
	obj.kind == "KubeletInfo"
	obj.apiVersion == "hostdata.kubescape.cloud/v1beta0"
}
