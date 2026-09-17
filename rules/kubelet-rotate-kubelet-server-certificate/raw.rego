# regal ignore:directory-package-mismatch
package armo_builtins

import rego.v1

# CIS 4.2.11 https://workbench.cisecurity.org/sections/1126668/recommendations/1838656
#
# The RotateKubeletServerCertificate feature gate has been beta and enabled by
# default since Kubernetes 1.12, and the control's own default_value records
# that rotation is enabled by default. CIS therefore audits for an explicit
# disable: a node passes when the gate is absent, and fails only when it is set
# to false. An absent gate must not fail this control.

## Feature gate explicitly disabled on the kubelet command line
deny contains msga if {
	some obj in input
	is_kubelet_info(obj)

	command := obj.data.cmdLine

	is_feature_gate_disabled_via_cli(command)

	external_obj := json.filter(obj, ["apiVersion", "data/cmdLine", "kind", "metadata"])

	msga := {
		"alertMessage": "RotateKubeletServerCertificate is set to false",
		"alertScore": 6,
		"reviewPaths": [],
		"failedPaths": [],
		"fixPaths": [],
		"packagename": "armo_builtins",
		"alertObject": {"externalObjects": external_obj},
	}
}

## Feature gate explicitly disabled in the kubelet config file
deny contains msga if {
	some obj in input
	is_kubelet_info(obj)

	command := obj.data.cmdLine

	not is_feature_gate_set_via_cli(command)

	decodedConfigContent := base64.decode(obj.data.configFile.content)
	yamlConfig := yaml.unmarshal(decodedConfigContent)

	yamlConfig.featureGates.RotateKubeletServerCertificate == false

	msga := {
		"alertMessage": "Property featureGates.RotateKubeletServerCertificate is set to false",
		"alertScore": 6,
		"reviewPaths": ["featureGates.RotateKubeletServerCertificate"],
		"failedPaths": ["featureGates.RotateKubeletServerCertificate"],
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

## Inner rules
is_kubelet_info(obj) if {
	obj.kind == "KubeletInfo"
	obj.apiVersion == "hostdata.kubescape.cloud/v1beta0"
}

is_feature_gate_set_via_cli(command) if {
	contains(command, "--feature-gates=")
	contains(command, "RotateKubeletServerCertificate=")
}

is_feature_gate_disabled_via_cli(command) if {
	contains(command, "--feature-gates=")
	contains(command, "RotateKubeletServerCertificate=false")
}
