package armo_builtins
import data.kubernetes.api.client as client

# Both config and cli present
deny[msga] {
		kubelet_config := input[_]
		kubelet_config.kind == "KubeletConfiguration"
		kubelet_config.apiVersion == "hostdata.kubescape.cloud/v1beta0"

		kubelet_cli := input[_]            
		kubelet_cli.kind == "KubeletCommandLine"
		kubelet_cli.apiVersion == "hostdata.kubescape.cloud/v1beta0"
		not is_read_only_port_disabled_both(kubelet_config, kubelet_cli)


		msga := {
			"alertMessage": "kubelet read-only port is not disabled",
			"alertScore": 2,
			"failedPaths": [],
			"fixPaths": [],
			"packagename": "armo_builtins",
			"alertObject": {
                "k8sApiObjects": [kubelet_config, kubelet_cli]
			},
		}
	}


# Only one of them present
deny[msga] {
		external_obj := is_read_only_port_enabled_single(input)

		msga := {
			"alertMessage": "kubelet read-only port is not disabled",
			"alertScore": 2,
			"failedPaths": [],
			"fixPaths": [],
			"packagename": "armo_builtins",
			"alertObject": {
                "k8sApiObjects": [external_obj]
			},
		}
	}


is_read_only_port_disabled_both(kubelet_config, kubelet_cli) {
     kubelet_config.data.readOnlyPort == 0
}

is_read_only_port_disabled_both(kubelet_config, kubelet_cli) {
    is_read_only_port_disabled_cli(kubelet_cli)
    not is_read_only_port_enabled_config(kubelet_config)
}

is_read_only_port_enabled_single(resources) = obj {
	kubelet_cli := resources[_]            
	kubelet_cli.kind == "KubeletCommandLine"
	kubelet_cli.apiVersion == "hostdata.kubescape.cloud/v1beta0"

	kubelet_config := [config | config = resources[_]; config.kind == "KubeletConfiguration"]
	count(kubelet_config) == 0

	not is_read_only_port_disabled_cli(kubelet_cli)
	
	obj = kubelet_cli
}


is_read_only_port_enabled_single(resources) = obj {
	kubelet_config := resources[_]
	kubelet_config.kind == "KubeletConfiguration"
	kubelet_config.apiVersion == "hostdata.kubescape.cloud/v1beta0"

	kubelet_cli := [cli | cli = resources[_]; cli.kind == "KubeletCommandLine"]
	count(kubelet_cli) == 0

	is_read_only_port_enabled_config(kubelet_config) 
	
	obj = kubelet_config
}


# 0 or not present -> disabled
is_read_only_port_disabled_cli(kubelet_cli) {
    kubelet_cli_data := kubelet_cli.data
    contains(kubelet_cli_data["fullCommand"], "--read-only-port=0")
}

is_read_only_port_disabled_cli(kubelet_cli) {
    kubelet_cli_data := kubelet_cli.data
    not contains(kubelet_cli_data["fullCommand"], "--read-only-port")
}

is_read_only_port_disabled_config(kubelet_config) {
    not kubelet_config.data.readOnlyPort
}

is_read_only_port_disabled_config(kubelet_config) {
    kubelet_config.data.readOnlyPort == 0
}

is_read_only_port_enabled_config(kubelet_config) {
    kubelet_config.data.readOnlyPort
    kubelet_config.data.readOnlyPort != 0
}
