package armo_builtins
import data.kubernetes.api.client as client

deny[msga] {
		kubelet_config := input[_]
		kubelet_config.kind == "KubeletConfiguration"
		kubelet_config.apiVersion == "hostdata.kubescape.cloud/v1beta0"

		kubelet_cli := input[_]            
		kubelet_cli.kind == "KubeletCommandLine"
		kubelet_cli.apiVersion == "hostdata.kubescape.cloud/v1beta0"

		external_obj := getObjBoth(kubelet_config, kubelet_cli)


		msga := {
			"alertMessage": "anonymous requests is enabled",
			"alertScore": 2,
			"failedPaths": [],
			"packagename": "armo_builtins",
			"alertObject": {
				"externalObjects": external_obj
			}
		}
	}


	
deny[msga] {

		external_obj := getObjSingle(input)


		msga := {
			"alertMessage": "anonymous requests is enabled",
			"alertScore": 2,
			"failedPaths": [],
			"packagename": "armo_builtins",
			"alertObject": {
				"externalObjects": external_obj
			}
		}
	}


# Both cli and config present. Return only relevant (priority to cli)
getObjBoth(kubelet_config, kubelet_cli) = obj {
	kubelet_cli_data := kubelet_cli.data
	contains(kubelet_cli_data["fullCommand"], "anonymous-auth=")
    obj = kubelet_cli
}


getObjBoth(kubelet_config, kubelet_cli) = obj {
	kubelet_cli_data := kubelet_cli.data
	not contains(kubelet_cli_data["fullCommand"], "anonymous-auth=")
    obj = kubelet_config
}

# Only cli or only config
getObjSingle(resources) = obj {
	kubelet_cli := resources[_]            
	kubelet_cli.kind == "KubeletCommandLine"
	kubelet_cli.apiVersion == "hostdata.kubescape.cloud/v1beta0"

	kubelet_config := [config | config = resources[_]; config.kind == "KubeletConfiguration"]
	count(kubelet_config) == 0

	obj = kubelet_cli
}

getObjSingle(resources) = obj {
	kubelet_config := resources[_]
	kubelet_config.kind == "KubeletConfiguration"
	kubelet_config.apiVersion == "hostdata.kubescape.cloud/v1beta0"

	kubelet_cli := [cli | cli = resources[_]; cli.kind == "KubeletCommandLine"]
	count(kubelet_cli) == 0

	obj = kubelet_config
}