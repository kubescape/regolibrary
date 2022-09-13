package armo_builtins

import future.keywords.in

# --hostname-override argument is not present
deny[msga] {
	kubelet_info := input[_]
	kubelet_info.kind == "KubeletInfo"
	kubelet_info.apiVersion == "hostdata.kubescape.cloud/v1beta0"
	command := kubelet_info.data.cmdLine

	contains(command, "--hostname-override")

	external_obj := json.filter(kubelet_info, ["apiVersion", "data/cmdLine", "kind"])

	msga := {
		"alertMessage": "Argument --hostname-override is set.",
		"alertScore": 3,
		"failedPaths": [],
		"fixPaths": [],
		"packagename": "armo_builtins",
		"alertObject": {"alertObject": external_obj},
	}
}
