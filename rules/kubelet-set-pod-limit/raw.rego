package armo_builtins

import rego.v1

# CIS 4.2.13 https://workbench.cisecurity.org/sections/2633393/recommendations/4262020

deny contains msga if {
	kubelet_info := input[_]
	kubelet_info.kind == "KubeletInfo"
	kubelet_info.apiVersion == "hostdata.kubescape.cloud/v1beta0"
	command := kubelet_info.data.cmdLine

	not contains(command, "--pod-max-pids")

	decodedConfigContent := base64.decode(kubelet_info.data.configFile.content)
	yamlConfig := yaml.unmarshal(decodedConfigContent)
	not yamlConfig.podPidsLimit

	external_obj := json.filter(kubelet_info, ["apiVersion", "data/cmdLine", "kind", "metadata"])

	msga := {
		"alertMessage": "Neither argument --pod-max-pids nor podPidsLimit is set.",
		"alertScore": 3,
		"failedPaths": [],
		"fixPaths": [],
		"packagename": "armo_builtins",
		"alertObject": {"externalObjects": external_obj},
	}
}
