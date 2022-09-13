package armo_builtins

import future.keywords.in

# has --tls-cipher-suites set via CLI
deny[msga] {
 	
    kubelet_info := input[_]
    kubelet_info.kind == "KubeletInfo"
    kubelet_info.apiVersion == "hostdata.kubescape.cloud/v1beta0"
    command := kubelet_info.data.cmdLine 

	contains(command, "--tls-cipher-suites")
	
    not has_strong_cipher_set_via_cli(command)
   
	external_obj := json.filter(kubelet_info, ["apiVersion", "data/cmdLine", "kind"])

    msga := {
        "alertMessage": "Used cipher is not strong",
        "alertScore": 2,
        "failedPaths": [],
        "fixPaths": [],
        "packagename": "armo_builtins",
        "alertObject": {"externalObjects": external_obj}
    }
}


# has --config argument present
deny[msga] {
 	
    kubelet_info := input[_]
    kubelet_info.kind == "KubeletInfo"
    kubelet_info.apiVersion == "hostdata.kubescape.cloud/v1beta0"
    command := kubelet_info.data.cmdLine 
    
    not contains(command, "--tls-cipher-suites")
    contains(command, "--config")
    
   
	decodedConfigContent := base64.decode(kubelet_info.data.configFile.content)
	yamlConfig := yaml.unmarshal(decodedConfigContent)
	yamlConfig.TLSCipherSuites
    
  	not is_value_in_strong_cliphers_set(yamlConfig.TLSCipherSuites)
   
    msga := {
        "alertMessage": "Kubelet is not configured to only use strong cryptographic ciphers",
        "alertScore": 5,
        "failedPaths": ["TLSCipherSuites"],
        "fixPaths": [],
        "packagename": "armo_builtins",
        "alertObject": {"externalObjects": {
			"apiVersion": kubelet_info.apiVersion,
			"kind": kubelet_info.kind,
			"data": {"configFile": {"content": decodedConfigContent}},
		}}

    }
}





## Inner rules
has_strong_cipher_set_via_cli(command) {
	
    contains(command, "--tls-cipher-suites=")
    
    strong_cliphers := [
        "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
        "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
        "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305",
        "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
        "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305",
        "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
        "TLS_RSA_WITH_AES_256_GCM_SHA384",
        "TLS_RSA_WITH_AES_128_GCM_SHA256"
    ]
    
    some i
        contains(command, sprintf("%v%v", ["--tls-cipher-suites=", strong_cliphers[i]]))
}


 
is_value_in_strong_cliphers_set(value){
  strong_cliphers := [
        "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
        "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
        "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305",
        "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
        "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305",
        "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
        "TLS_RSA_WITH_AES_256_GCM_SHA384",
        "TLS_RSA_WITH_AES_128_GCM_SHA256"
    ]
    some x
       strong_cliphers[x] == value
}
 