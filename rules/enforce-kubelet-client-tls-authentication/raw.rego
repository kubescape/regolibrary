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
		kubelet_cli_data := kubelet_cli.data

		result := is_client_tls_disabled_both(kubelet_config, kubelet_cli_data)
		external_obj := result.obj
		failed_paths := result.failedPaths
		fixPaths := result.fixPaths


		msga := {
			"alertMessage": "kubelet client TLS authentication is not enabled",
			"alertScore": 2,
			"failedPaths": failed_paths,
			"fixPaths": fixPaths,
			"packagename": "armo_builtins",
			"alertObject": {
				"k8sApiObjects": [kubelet_config, kubelet_cli]
			},
		}
	}


# Only of them present
deny[msga] {
		result := is_client_tls_disabled_single(input)
		external_obj := result.obj
		failed_paths := result.failedPaths
		fixPaths := result.fixPaths

		msga := {
			"alertMessage": "kubelet client TLS authentication is not enabled",
			"alertScore": 2,
			"failedPaths": failed_paths,
			"fixPaths": fixPaths,
			"packagename": "armo_builtins",
			"alertObject": {
				"k8sApiObjects": [external_obj]
			},
		}
	}

# CLI overrides config
is_client_tls_disabled_both(kubelet_config, kubelet_cli_data) = {"obj": obj,"failedPaths": [], "fixPaths": [{"path": "data.authentication.x509.clientCAFile",  "value": "YOUR_VALUE"}]}  {
	not contains(kubelet_cli_data["fullCommand"], "client-ca-file")
    not kubelet_config.data.authentication.x509.clientCAFile
	obj = kubelet_config
}

# Only cli
is_client_tls_disabled_single(resources) = {"obj": obj,"failedPaths": [], "fixPaths": []}  {
	kubelet_cli := resources[_]            
	kubelet_cli.kind == "KubeletCommandLine"
	kubelet_cli.apiVersion == "hostdata.kubescape.cloud/v1beta0"

	kubelet_config := [config | config = resources[_]; config.kind == "KubeletConfiguration"]
	count(kubelet_config) == 0

	obj = isClientTlsDisabledCli(kubelet_cli)
	
}

# Only config
is_client_tls_disabled_single(resources) = {"obj": obj,"failedPaths": [], "fixPaths": [{"path": "data.authentication.x509.clientCAFile",  "value": "YOUR_VALUE"}]}  {
	kubelet_config := resources[_]            
	kubelet_config.kind == "KubeletConfiguration"
	kubelet_config.apiVersion == "hostdata.kubescape.cloud/v1beta0"

	kubelet_cmd := [cmd | cmd = resources[_]; cmd.kind == "KubeletCommandLine"]
	count(kubelet_cmd) == 0

	obj = is_Client_tls_disabled_config(kubelet_config)
}


is_Client_tls_disabled_config(kubelet_config) = obj {
	not kubelet_config.data.authentication.x509.clientCAFile
	obj = kubelet_config
}

isClientTlsDisabledCli(kubelet_cli) = obj {
	kubelet_cli_data = kubelet_cli.data
	not contains(kubelet_cli_data["fullCommand"], "client-ca-file")
	obj = kubelet_cli
}