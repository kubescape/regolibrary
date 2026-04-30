package armo_builtins

import future.keywords.in

# CIS 4.3.1 - Ensure that the kube-proxy metrics service is bound to localhost

# Deny if metricsBindAddress is exposed on all interfaces (0.0.0.0)
deny[msga] {
	configmap := input[_]
	is_kube_proxy_configmap(configmap)

	config_data := get_config_data(configmap)
	config := yaml.unmarshal(config_data)

	metrics_address := config.metricsBindAddress

	# Fail if bound to all interfaces
	startswith(metrics_address, "0.0.0.0")

	msga := {
		"alertMessage": sprintf("kube-proxy metrics service is bound to all interfaces (%s) instead of localhost", [metrics_address]),
		"alertScore": 7,
		"failedPaths": ["data"],
		"fixPaths": [],
		"packagename": "armo_builtins",
		"alertObject": {"k8sApiObjects": [configmap]},
	}
}

# Deny if metricsBindAddress is missing (may default to 0.0.0.0)
deny[msga] {
	configmap := input[_]
	is_kube_proxy_configmap(configmap)

	config_data := get_config_data(configmap)
	config := yaml.unmarshal(config_data)

	not config.metricsBindAddress

	msga := {
		"alertMessage": "kube-proxy metrics service binding address is not configured (may default to all interfaces)",
		"alertScore": 7,
		"failedPaths": ["data"],
		"fixPaths": [],
		"packagename": "armo_builtins",
		"alertObject": {"k8sApiObjects": [configmap]},
	}
}

# Deny if metricsBindAddress is empty string
deny[msga] {
	configmap := input[_]
	is_kube_proxy_configmap(configmap)

	config_data := get_config_data(configmap)
	config := yaml.unmarshal(config_data)

	config.metricsBindAddress == ""

	msga := {
		"alertMessage": "kube-proxy metrics service binding address is empty (may default to all interfaces)",
		"alertScore": 7,
		"failedPaths": ["data"],
		"fixPaths": [],
		"packagename": "armo_builtins",
		"alertObject": {"k8sApiObjects": [configmap]},
	}
}

# Helper: Check if this is the kube-proxy ConfigMap
is_kube_proxy_configmap(configmap) {
	configmap.kind == "ConfigMap"
	configmap.metadata.name == "kube-proxy"
	configmap.metadata.namespace == "kube-system"
}

# Helper: Get config data from ConfigMap (try different field names)
get_config_data(configmap) := value {
	value := object.get(configmap.data, "config.conf", "")
	value != ""
}

get_config_data(configmap) := value {
	not configmap.data["config.conf"]
	value := object.get(configmap.data, "kubeconfig.conf", "")
	value != ""
}

get_config_data(configmap) := value {
	not configmap.data["config.conf"]
	not configmap.data["kubeconfig.conf"]
	value := object.get(configmap.data, "config", "")
	value != ""
}
