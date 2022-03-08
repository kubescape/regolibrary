package armo_builtins
import data.kubernetes.api.client as client

deny[msga] {
		kubeletConfig := input[_]
		kubeletConfig.kind == "KubeletConfiguration"
		kubeletConfig.apiVersion == "hostdata.kubescape.cloud/v1beta0"

		kubeletCli := input[_]            
		kubeletCli.kind == "KubeletCommandLine"
		kubeletCli.apiVersion == "hostdata.kubescape.cloud/v1beta0"

		externalObj := getObjBoth(kubeletConfig, kubeletCli)


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


	
deny[msga] {

		externalObj := getObjSingle(input)


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


# Both cli and config present. Return only relevant (priority to cli)
getObjBoth(kubeletConfig, kubeletCli) = obj {
	kubeletCliData := kubeletCli.data
	contains(kubeletCliData["fullCommand"], "anonymous-auth=")
    obj = kubeletCli
}


getObjBoth(kubeletConfig, kubeletCli) = obj {
	kubeletCliData := kubeletCli.data
	not contains(kubeletCliData["fullCommand"], "anonymous-auth=")
    obj = kubeletConfig
}

# Only cli or only config
getObjSingle(resources) = obj {
	kubeletCli := resources[_]            
	kubeletCli.kind == "KubeletCommandLine"
	kubeletCli.apiVersion == "hostdata.kubescape.cloud/v1beta0"

	kubeletConfig := [config | config = resources[_]; config.kind == "KubeletConfiguration"]
	count(kubeletConfig) == 0

	obj = kubeletCli
}

getObjSingle(resources) = obj {
	kubeletConfig := resources[_]
	kubeletConfig.kind == "KubeletConfiguration"
	kubeletConfig.apiVersion == "hostdata.kubescape.cloud/v1beta0"

	kubeletCli := [cli | cli = resources[_]; cli.kind == "KubeletCommandLine"]
	count(kubeletCli) == 0

	obj = kubeletConfig
}