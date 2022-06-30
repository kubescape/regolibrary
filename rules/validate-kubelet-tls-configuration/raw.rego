package armo_builtins
import data.kubernetes.api.client as client

deny[msga] {
		kubelet_config := input[_]
		kubelet_config.kind == "KubeletConfiguration"
		kubelet_config.apiVersion == "hostdata.kubescape.cloud/v1beta0"

		kubelet_cli := input[_]            
		kubelet_cli.kind == "KubeletCommandLine"
		kubelet_cli.apiVersion == "hostdata.kubescape.cloud/v1beta0"
		kubelet_cli_data := kubelet_cli.data

		is_tls_disabled_both(kubelet_config, kubelet_cli_data)


		msga := {
			"alertMessage": "kubelet client TLS authentication is not enabled",
			"alertScore": 2,
			"fixPaths": [],
			"failedPaths": [],
			"packagename": "armo_builtins",
			"alertObject": {
                "k8sApiObjects": [kubelet_config, kubelet_cli]
			},
		}
	}


deny[msga] {
		external_obj := is_tls_disabled_single(input)


		msga := {
			"alertMessage": "kubelet client TLS authentication is not enabled",
			"alertScore": 2,
			"fixPaths": [],
			"failedPaths": [],
			"packagename": "armo_builtins",
			"alertObject": {
                "k8sApiObjects": [external_obj]
			},
		}
	}



# CLI overrides config
is_tls_disabled_both(kubelet_config, kubelet_cli) {
    is_not_tls_cli(kubelet_cli)
    is_not_tls_config(kubelet_config)
}

is_tls_disabled_single(resources) = obj {
	kubelet_cli := resources[_]            
	kubelet_cli.kind == "KubeletCommandLine"
	kubelet_cli.apiVersion == "hostdata.kubescape.cloud/v1beta0"

	kubelet_config := [config | config = resources[_]; config.kind == "KubeletConfiguration"]
	count(kubelet_config) == 0

	is_not_tls_cli(kubelet_cli)

	obj = kubelet_cli
}


is_tls_disabled_single(resources) = obj {
	kubelet_config := resources[_]
	kubelet_config.kind == "KubeletConfiguration"
	kubelet_config.apiVersion == "hostdata.kubescape.cloud/v1beta0"

	kubelet_cli := [cli | cli = resources[_]; cli.kind == "KubeletCommandLine"]
	count(kubelet_cli) == 0

	is_not_tls_config(kubelet_config)

	obj = kubelet_config
}


is_not_tls_cli(kubelet_cli) {
	kubelet_cli_data := kubelet_cli.data
	not contains(kubelet_cli_data["fullCommand"], "tls-cert-file")
	not contains(kubelet_cli_data["fullCommand"], "tls-private-key-file")
}

is_not_tls_config(kubelet_config){
    not kubelet_config.data.tlsCertFile
    not kubelet_config.data.tlsPrivateKeyFile
}
