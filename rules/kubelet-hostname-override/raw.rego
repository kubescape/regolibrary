package armo_builtins

import future.keywords.in

# CIS 4.2.8 https://workbench.cisecurity.org/sections/1126668/recommendations/1838654

deny[msga] {
	kubelet_info := input[_]
	kubelet_info.kind == "KubeletInfo"
	kubelet_info.apiVersion == "hostdata.kubescape.cloud/v1beta0"
	command := kubelet_info.data.cmdLine

	contains(command, "--hostname-override")

	external_obj := json.filter(kubelet_info, ["apiVersion", "data/cmdLine", "kind", "metadata"])

	msga := {
		"alertMessage": "Argument --hostname-override is set.",
		"alertScore": 3,
		"failedPaths": [],
		"fixPaths": [],
		"packagename": "armo_builtins",
		"alertObject": {"externalObjects": external_obj},
	}
}
