package armo_builtins
import data.kubernetes.api.client as client

deny[msga] {
		kubeletConfig := input[_]
		kubeletConfig.kind == "KubeletConfiguration"
		kubeletConfig.apiVersion == "hostdata.armo.cloud/v1beta0"

		kubeletCli := input[_]            
		kubeletCli.kind == "KubeletCommandLine"
		kubeletCli.apiVersion == "hostdata.armo.cloud/v1beta0"

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
	flag := kubeletCli.data["anonymous-auth"]
	flag == true
    obj := kubeletCli
}

isAnonymouRequestsDisabled(kubeletConfig, kubeletCli) = obj {
	kubeletConfig.data.authentication.anonymous.enabled == true
	not kubeletCli.data["anonymous-auth"] == false
    not kubeletCli.data["anonymous-auth"] == true
    obj := kubeletConfig
}