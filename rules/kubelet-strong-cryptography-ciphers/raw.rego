package armo_builtins

import rego.v1

# CIS 4.2.13 https://workbench.cisecurity.org/sections/1126668/recommendations/1838663

deny contains msga if {
	obj := input[_]
	is_kubelet_info(obj)

	command := obj.data.cmdLine

	contains(command, "--tls-cipher-suites")

	not has_strong_cipher_set_via_cli(command)

	external_obj := json.filter(obj, ["apiVersion", "data/cmdLine", "kind", "metadata"])

	msga := {
		"alertMessage": "Kubelet is not configured to only use strong cryptographic ciphers",
		"alertScore": 5,
		"reviewPaths": [],
		"failedPaths": [],
		"fixPaths": [],
		"packagename": "armo_builtins",
		"alertObject": {"externalObjects": external_obj},
	}
}

deny contains msga if {
	obj := input[_]
	is_kubelet_info(obj)

	command := obj.data.cmdLine

	not contains(command, "--tls-cipher-suites")
	contains(command, "--config")

	decodedConfigContent := base64.decode(obj.data.configFile.content)
	yamlConfig := yaml.unmarshal(decodedConfigContent)
	yamlConfig.TLSCipherSuites

	not is_value_in_strong_cliphers_set(yamlConfig.TLSCipherSuites)

	msga := {
		"alertMessage": "Kubelet is not configured to only use strong cryptographic ciphers",
		"alertScore": 5,
		"reviewPaths": ["TLSCipherSuites"],
		"failedPaths": ["TLSCipherSuites"],
		"fixPaths": [],
		"packagename": "armo_builtins",
		"alertObject": {"externalObjects": {
			"apiVersion": obj.apiVersion,
			"kind": obj.kind,
			"metadata": obj.metadata,
			"data": {"configFile": {"content": decodedConfigContent}},
		}},
	}
}

deny contains msga if {
	obj := input[_]
	is_kubelet_info(obj)

	command := obj.data.cmdLine

	not contains(command, "--tls-cipher-suites")
	not contains(command, "--config")

	external_obj := json.filter(obj, ["apiVersion", "data/cmdLine", "kind", "metadata"])

	msga := {
		"alertMessage": "Kubelet is not configured to only use strong cryptographic ciphers",
		"alertScore": 5,
		"reviewPaths": [],
		"failedPaths": [],
		"fixPaths": [],
		"packagename": "armo_builtins",
		"alertObject": {"externalObjects": external_obj},
	}
}

has_strong_cipher_set_via_cli(command) if {
	contains(command, "--tls-cipher-suites=")

	strong_cliphers := [
		"TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
		"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
		"TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305",
		"TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
		"TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305",
		"TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
		"TLS_RSA_WITH_AES_256_GCM_SHA384",
		"TLS_RSA_WITH_AES_128_GCM_SHA256",
	]

	some i
	contains(command, sprintf("%v%v", ["--tls-cipher-suites=", strong_cliphers[i]]))
}

is_value_in_strong_cliphers_set(value) if {
	strong_cliphers := [
		"TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
		"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
		"TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305",
		"TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
		"TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305",
		"TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
		"TLS_RSA_WITH_AES_256_GCM_SHA384",
		"TLS_RSA_WITH_AES_128_GCM_SHA256",
	]

	some x
	strong_cliphers[x] == value
}

is_kubelet_info(obj) if {
	obj.kind == "KubeletInfo"
	obj.apiVersion == "hostdata.kubescape.cloud/v1beta0"
}
