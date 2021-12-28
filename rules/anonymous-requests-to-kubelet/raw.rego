package armo_builtins
import data.kubernetes.api.client as client

deny[msga] {
		kubeletConfig := input[_]
		kubeletConfig.kind == "KubeletConfiguration"
		kubeletConfig.apiVersion == "hostdata.kubescape.cloud/v1beta0"

		kubeletCli := input[_]            
		kubeletCli.kind == "KubeletCommandLine"
		kubeletCli.apiVersion == "hostdata.kubescape.cloud/v1beta0"
		

		externalObj := isAnonymouRequestsDisabled(kubeletConfig, kubeletCli)


		msga := {
			"alertMessage": "anonymous requests is enabled",
			"alertScore": 2,
			"failedPaths": [],
			"packagename": "armo_builtins",
			"alertObject": {
				"externalObjects": externalObj
			}
		}
	}

# CLI overrides config
isAnonymouRequestsDisabled(kubeletConfig, kubeletCli) = obj {
	kubeletCliData := kubeletCli.data
	contains(kubeletCliData["fullCommand"], "anonymous-auth=true")
    obj := kubeletCli
}

isAnonymouRequestsDisabled(kubeletConfig, kubeletCli) = obj {
	kubeletConfig.data.authentication.anonymous.enabled == true
	kubeletCliData := kubeletCli.data
	not contains(kubeletCliData["fullCommand"], "anonymous-auth=false")
    not contains(kubeletCliData["fullCommand"], "anonymous-auth=true")
    obj := kubeletConfig
}