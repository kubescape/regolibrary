package armo_builtins
import data.kubernetes.api.client as client

deny[msga] {
		kubeletConfig := input[_]
		kubeletConfig.kind == "KubeletConfiguration"
		kubeletConfig.apiVersion == "hostdata.kubescape.cloud/v1beta0"

		kubeletCli := input[_]            
		kubeletCli.kind == "KubeletCommandLine"
		kubeletCli.apiVersion == "hostdata.kubescape.cloud/v1beta0"

		externalObj := getObj(kubeletConfig, kubeletCli)


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

getObj(kubeletConfig, kubeletCli) = obj {
	kubeletCli.data["anonymous-auth"] == false
    obj := kubeletCli
}

getObj(kubeletConfig, kubeletCli) = obj {
	kubeletCli.data["anonymous-auth"] == true
    obj := kubeletCli
}

getObj(kubeletConfig, kubeletCli) = obj {
	not kubeletCli.data["anonymous-auth"] == true
    not kubeletCli.data["anonymous-auth"] == false
    obj := kubeletConfig
}