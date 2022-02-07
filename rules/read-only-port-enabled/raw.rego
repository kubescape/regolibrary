package armo_builtins
import data.kubernetes.api.client as client

deny[msga] {
		kubeletConfig := input[_]
		kubeletConfig.kind == "KubeletConfiguration"
		kubeletConfig.apiVersion == "hostdata.kubescape.cloud/v1beta0"

		kubeletCli := input[_]            
		kubeletCli.kind == "KubeletCommandLine"
		kubeletCli.apiVersion == "hostdata.kubescape.cloud/v1beta0"
		not isReadOnlyPortDisabled(kubeletConfig, kubeletCli)


		msga := {
			"alertMessage": "kubelet read-only port is not disabled",
			"alertScore": 2,
			"failedPaths": [],
			"packagename": "armo_builtins",
			"alertObject": {
                "k8sApiObjects": [kubeletConfig, kubeletCli]
			},
		}
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

isReadOnlyPortDisabled(kubeletConfig, kubeletCli) {
     kubeletConfig.data.readOnlyPort == 0
}

isReadOnlyPortDisabled(kubeletConfig, kubeletCli) {
    isReadOnlyPortDisabledCli(kubeletCli)
    isReadOnlyPortDisabledConfig(kubeletConfig)
    not isReadOnlyPortEnabledConfig(kubeletConfig)
}

# kubelet config takes precedence
isReadOnlyPortEnabledConfig(kubeletConfig) {
    kubeletConfig.data.readOnlyPort
    kubeletConfig.data.readOnlyPort != 0
}