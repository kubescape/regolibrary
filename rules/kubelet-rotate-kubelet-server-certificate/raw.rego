package armo_builtins

import future.keywords.in

deny[msga] {
	kubelet_info := input[_]
	kubelet_info.kind == "KubeletInfo"
	kubelet_info.apiVersion == "hostdata.kubescape.cloud/v1beta0"

	not should_skip_check(kubelet_info)

	command := kubelet_info.data.cmdLine

	not is_RotateKubeletServerCertificate_enabled_via_cli(command)

	external_obj := json.filter(kubelet_info, ["apiVersion", "data/cmdLine", "kind", "metadata"])

	msga := {
		"alertMessage": "RotateKubeletServerCertificate is not set to true",
		"alertScore": 6,
		"failedPaths": [],
		"fixPaths": [],
		"packagename": "armo_builtins",
		"alertObject": {"externalObjects": external_obj},
	}
}

## Inner rules
should_skip_check(kubelet_info) {
	command := kubelet_info.data.cmdLine
	contains(command, "--rotate-server-certificates")
}

should_skip_check(kubelet_info) {
	yamlConfigContent := yaml.unmarshal(base64.decode(kubelet_info.data.configFile.content))
	yamlConfigContent.serverTLSBootstrap == true
}

is_RotateKubeletServerCertificate_enabled_via_cli(command) {
	contains(command, "--feature-gates=")
	args := regex.split(` +`, command)
	some i
	regex.match(`RotateKubeletServerCertificate=true`, args[i])
}
