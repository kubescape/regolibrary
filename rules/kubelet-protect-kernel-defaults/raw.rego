package armo_builtins

import future.keywords.in

# --protect-kernel-defaults argument is present
deny[msga] {
 	
    kubelet_info := input[_]
    kubelet_info.kind == "KubeletInfo"
    kubelet_info.apiVersion == "hostdata.kubescape.cloud/v1beta0"
   	command := kubelet_info.data.cmdLine 
    
    
    contains(command, "--protect-kernel-defaults")
    not contains(command, "--protect-kernel-defaults=true")

    external_obj := json.filter(kubelet_info, ["apiVersion", "data/cmdLine", "kind"])

    msga := {
        "alertMessage": "Argument --protect-kernel-defaults is not set to true.",
        "alertScore": 2,
        "failedPaths": [],
        "fixPaths": [],
        "packagename": "armo_builtins",
        "alertObject": {
           "alertObject": external_obj
        }

    }
}

# --protect-kernel-defaults argument is not present, check in config file
deny[msga] {
 	
  	kubelet_info := input[_]
    kubelet_info.kind == "KubeletInfo"
    kubelet_info.apiVersion == "hostdata.kubescape.cloud/v1beta0"
   	command := kubelet_info.data.cmdLine 
    
    not contains(command, "--protect-kernel-defaults")
	contains(command, "--config")
    
    
    decodedConfigContent := base64.decode(kubelet_info.data.configFile.content)
	yamlConfig := yaml.unmarshal(decodedConfigContent) 
	not yamlConfig.protectKernelDefaults == true
      
    msga := {
        "alertMessage": "Property protectKernelDefaults is not set to true",
        "alertScore": 2,
        "failedPaths": ["protectKernelDefaults"],
        "fixPaths": [],
        "packagename": "armo_builtins",
        "alertObject":  {"externalObjects": {
			"apiVersion": kubelet_info.apiVersion,
			"kind": kubelet_info.kind,
			"data": {"configFile": {"content": decodedConfigContent}},
		}}

    }
}
