package armo_builtins
import data.kubernetes.api.client as client

# Both config and cli present
deny[msga] {
		kubeletConfig := input[_]
		kubeletConfig.kind == "KubeletConfiguration"
		kubeletConfig.apiVersion == "hostdata.kubescape.cloud/v1beta0"

		kubeletCli := input[_]            
		kubeletCli.kind == "KubeletCommandLine"
		kubeletCli.apiVersion == "hostdata.kubescape.cloud/v1beta0"
		not isReadOnlyPortDisabledBoth(kubeletConfig, kubeletCli)


		msga := {
			"alertMessage": "kubelet read-only port is not disabled",
			"alertScore": 2,
			"failedPaths": [],
			"fixPaths": [],
			"packagename": "armo_builtins",
			"alertObject": {
                "k8sApiObjects": [kubeletConfig, kubeletCli]
			},
		}
	}


# Only one of them present
deny[msga] {
		externalObj := isReadOnlyPortEnabledSingle(input)

		msga := {
			"alertMessage": "kubelet read-only port is not disabled",
			"alertScore": 2,
			"failedPaths": [],
			"fixPaths": [],
			"packagename": "armo_builtins",
			"alertObject": {
                "k8sApiObjects": [externalObj]
			},
		}
	}


isReadOnlyPortDisabledBoth(kubeletConfig, kubeletCli) {
     kubeletConfig.data.readOnlyPort == 0
}

isReadOnlyPortDisabledBoth(kubeletConfig, kubeletCli) {
    isReadOnlyPortDisabledCli(kubeletCli)
    not isReadOnlyPortEnabledConfig(kubeletConfig)
}

isReadOnlyPortEnabledSingle(resources) = obj {
	kubeletCli := resources[_]            
	kubeletCli.kind == "KubeletCommandLine"
	kubeletCli.apiVersion == "hostdata.kubescape.cloud/v1beta0"

	kubeletConfig := [config | config = resources[_]; config.kind == "KubeletConfiguration"]
	count(kubeletConfig) == 0

	not isReadOnlyPortDisabledCli(kubeletCli)
	
	obj = kubeletCli
}


isReadOnlyPortEnabledSingle(resources) = obj {
	kubeletConfig := resources[_]
	kubeletConfig.kind == "KubeletConfiguration"
	kubeletConfig.apiVersion == "hostdata.kubescape.cloud/v1beta0"

	kubeletCli := [cli | cli = resources[_]; cli.kind == "KubeletCommandLine"]
	count(kubeletCli) == 0

	isReadOnlyPortEnabledConfig(kubeletConfig) 
	
	obj = kubeletConfig
}


# 0 or not present -> disabled
isReadOnlyPortDisabledCli(kubeletCli) {
    kubeletCliData := kubeletCli.data
    contains(kubeletCliData["fullCommand"], "--read-only-port=0")
}

isReadOnlyPortDisabledCli(kubeletCli) {
    kubeletCliData := kubeletCli.data
    not contains(kubeletCliData["fullCommand"], "--read-only-port")
}

isReadOnlyPortDisabledConfig(kubeletConfig) {
    not kubeletConfig.data.readOnlyPort
}

isReadOnlyPortDisabledConfig(kubeletConfig) {
    kubeletConfig.data.readOnlyPort == 0
}

isReadOnlyPortEnabledConfig(kubeletConfig) {
    kubeletConfig.data.readOnlyPort
    kubeletConfig.data.readOnlyPort != 0
}
