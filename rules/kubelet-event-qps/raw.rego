package armo_builtins

import future.keywords.in

# if --event-qps is present rule should pass

# --event-qps argument is not present
deny[msga] {
 	
    kubelet_info := input[_]
    kubelet_info.kind == "KubeletInfo"
    kubelet_info.apiVersion == "hostdata.kubescape.cloud/v1beta0"
    command := kubelet_info.data.cmdLine
    
    not contains(command, "--event-qps")
    contains(command, "--config")    

    decodedConfigContent := base64.decode(kubelet_info.data.configFile.content)
	yamlConfig := yaml.unmarshal(decodedConfigContent)
	yamlConfig.eventRecordQPS == 0
      
    msga := {
        "alertMessage": "Value of the eventRecordQPS argument is set to 0",
        "alertScore": 2,
        "failedPaths": ["eventRecordQPS"],
        "fixPaths": [],
        "packagename": "armo_builtins",
        "alertObject": {"externalObjects": {
			"apiVersion": kubelet_info.apiVersion,
			"kind": kubelet_info.kind,
			"data": {"configFile": {"content": decodedConfigContent}},
		}}

    }
}