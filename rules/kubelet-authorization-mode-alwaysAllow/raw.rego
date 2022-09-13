package armo_builtins

import future.keywords.in

# has --authorization-mode set to AlwaysAllow via CLI
deny[msga] {
	kubelet_info := input[_]
	kubelet_info.kind == "KubeletInfo"
	kubelet_info.apiVersion == "hostdata.kubescape.cloud/v1beta0"
	command := kubelet_info.data.cmdLine

	contains(command, "--authorization-mode")
    contains(command, "--authorization-mode=AlwaysAllow")
	
    external_obj := json.filter(kubelet_info, ["apiVersion", "data/cmdLine", "kind"])
    
	msga := {
		"alertMessage": "Anonymous requests are enabled",
		"alertScore": 10,
		"failedPaths": [],
		"fixPaths": [],
		"packagename": "armo_builtins",
		"alertObject": {"externalObjects": external_obj}
	}
}

# has no --authorization-mode argument present in the command
deny[msga] {
	kubelet_info := input[_]
	kubelet_info.kind == "KubeletInfo"
	kubelet_info.apiVersion == "hostdata.kubescape.cloud/v1beta0"
	command := kubelet_info.data.cmdLine

	not contains(command, "--authorization-mode")
	contains(command, "--config")

	decodedConfigContent := base64.decode(kubelet_info.data.configFile.content)
    yamlConfig := yaml.unmarshal(decodedConfigContent)
	yamlConfig.authorization.mode == "AlwaysAllow"

	msga := {
		"alertMessage": "Anonymous requests are enabled",
		"alertScore": 10,
		"failedPaths": ["authorization.mode"],
		"fixPaths": [],
		"packagename": "armo_builtins",
			"alertObject": {"externalObjects": {
        	"apiVersion": kubelet_info.apiVersion,
            "kind": kubelet_info.kind,
            "data": {
            	"configFile": {
                "content": decodedConfigContent
                }
            }
        }}
	}
}
