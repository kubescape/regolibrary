package armo_builtins
import data.kubernetes.api.client as client

deny[msga] {
		kubeletConfig := input[_]
		kubeletConfig.kind == "KubeletConfiguration"
		kubeletConfig.apiVersion == "hostdata.kubescape.cloud/v1beta0"

		kubeletCli := input[_]            
		kubeletCli.kind == "KubeletCommandLine"
		kubeletCli.apiVersion == "hostdata.kubescape.cloud/v1beta0"
		
		externalObj := isAnonymouRequestsDisabledBoth(kubeletConfig, kubeletCli)


		msga := {
			"alertMessage": "anonymous requests is enabled",
			"alertScore": 2,
			"failedPaths": [],
			"fixPaths":[],
			"packagename": "armo_builtins",
			"alertObject": {
				"externalObjects": externalObj
			}
		}
	}


deny[msga] {
		externalObj := isAnonymouRequestsDisabledSingle(input)

		msga := {
			"alertMessage": "anonymous requests is enabled",
			"alertScore": 2,
			"failedPaths": [],
			"fixPaths":[],
			"packagename": "armo_builtins",
			"alertObject": {
				"externalObjects": externalObj
			}
		}
	}

# CLI overrides config
isAnonymouRequestsDisabledBoth(kubeletConfig, kubeletCli) = obj {
	kubeletCliData := kubeletCli.data
	contains(kubeletCliData["fullCommand"], "anonymous-auth=true")
    obj = kubeletCli
}

isAnonymouRequestsDisabledBoth(kubeletConfig, kubeletCli) = obj {
	kubeletConfig.data.authentication.anonymous.enabled == true
	kubeletCliData := kubeletCli.data
	not contains(kubeletCliData["fullCommand"], "anonymous-auth=false")
    not contains(kubeletCliData["fullCommand"], "anonymous-auth=true")
    obj = kubeletConfig
}

# only kubelet config
isAnonymouRequestsDisabledSingle(resources) = obj {
	kubeletConfig := resources[_]
	kubeletConfig.kind == "KubeletConfiguration"
	kubeletConfig.apiVersion == "hostdata.kubescape.cloud/v1beta0"

	kubeletCli := [cli | cli = resources[_]; cli.kind == "KubeletCommandLine"]
	count(kubeletCli) == 0

	obj = isAnonymouRequestsDisabledKubeletConfig(kubeletConfig) 
}

# only kubelet cli
isAnonymouRequestsDisabledSingle(resources) = obj {
	kubeletCli := resources[_]            
	kubeletCli.kind == "KubeletCommandLine"
	kubeletCli.apiVersion == "hostdata.kubescape.cloud/v1beta0"

	kubeletConfig := [config | config = resources[_]; config.kind == "KubeletConfiguration"]
	count(kubeletConfig) == 0

	obj = isAnonymouRequestsDisabledKubeletCli(kubeletCli)
}


isAnonymouRequestsDisabledKubeletConfig(kubeletConfig) = obj {
	kubeletConfig.data.authentication.anonymous.enabled == true
	obj = kubeletConfig
}


isAnonymouRequestsDisabledKubeletCli(kubeletCli) = obj {
	kubeletCliData := kubeletCli.data
	contains(kubeletCliData["fullCommand"], "anonymous-auth=true")
    obj = kubeletCli
}