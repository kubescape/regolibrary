package armo_builtins
import data.kubernetes.api.client as client

deny[msga] {
		kubelet_config := input[_]
		kubelet_config.kind == "KubeletConfiguration"
		kubelet_config.apiVersion == "hostdata.kubescape.cloud/v1beta0"

		kubelet_cli := input[_]            
		kubelet_cli.kind == "KubeletCommandLine"
		kubelet_cli.apiVersion == "hostdata.kubescape.cloud/v1beta0"
		
		result := is_anonymou_requests_disabled_both(kubelet_config, kubelet_cli)
		external_obj := result.obj
		failed_paths := result.failedPaths
		fix_paths := result.fixPaths

		msga := {
			"alertMessage": "anonymous requests is enabled",
			"alertScore": 2,
			"failedPaths": failed_paths,
			"fixPaths": fix_paths,
			"packagename": "armo_builtins",
			"alertObject": {
				"externalObjects": external_obj
			}
		}
	}


deny[msga] {
		result := is_anonymou_requests_disabled_single(input)
		external_obj := result.obj
		failed_paths := result.failedPaths
		fix_paths := result.fixPaths

		msga := {
			"alertMessage": "anonymous requests is enabled",
			"alertScore": 2,
			"failedPaths": failed_paths,
			"fixPaths": fix_paths,
			"packagename": "armo_builtins",
			"alertObject": {
				"externalObjects": external_obj
			}
		}
	}

# CLI overrides config
is_anonymou_requests_disabled_both(kubelet_config, kubelet_cli) = {"obj": obj,"failedPaths": [], "fixPaths": []} {
	kubelet_cli_data := kubelet_cli.data
	contains(kubelet_cli_data["fullCommand"], "anonymous-auth=true")
	obj = kubelet_cli
}

is_anonymou_requests_disabled_both(kubelet_config, kubelet_cli) = {"obj": obj,"failedPaths": ["data.authentication.anonymous.enabled"], "fixPaths": []} {
	kubelet_config.data.authentication.anonymous.enabled == true
	kubelet_cli_data := kubelet_cli.data
	not contains(kubelet_cli_data["fullCommand"], "anonymous-auth=false")
    not contains(kubelet_cli_data["fullCommand"], "anonymous-auth=true")
	obj = kubelet_config
}

# only kubelet config
is_anonymou_requests_disabled_single(resources) =  {"obj": obj,"failedPaths": ["data.authentication.anonymous.enabled"], "fixPaths": []} {
	kubelet_config := resources[_]
	kubelet_config.kind == "KubeletConfiguration"
	kubelet_config.apiVersion == "hostdata.kubescape.cloud/v1beta0"

	kubelet_cli := [cli | cli = resources[_]; cli.kind == "KubeletCommandLine"]
	count(kubelet_cli) == 0

	obj = isAnonymouRequestsDisabledKubeletConfig(kubelet_config) 
}

# only kubelet cli
is_anonymou_requests_disabled_single(resources) = {"obj": obj,"failedPaths": [], "fixPaths": []} {
	kubelet_cli := resources[_]            
	kubelet_cli.kind == "KubeletCommandLine"
	kubelet_cli.apiVersion == "hostdata.kubescape.cloud/v1beta0"

	kubelet_config := [config | config = resources[_]; config.kind == "KubeletConfiguration"]
	count(kubelet_config) == 0

	obj = isAnonymouRequestsDisabledKubeletCli(kubelet_cli)
}


isAnonymouRequestsDisabledKubeletConfig(kubelet_config) = obj {
	kubelet_config.data.authentication.anonymous.enabled == true
	obj = kubelet_config
}


isAnonymouRequestsDisabledKubeletCli(kubelet_cli) = obj {
	kubelet_cli_data := kubelet_cli.data
	contains(kubelet_cli_data["fullCommand"], "anonymous-auth=true")
    obj = kubelet_cli
}