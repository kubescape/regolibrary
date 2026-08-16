# regal ignore:directory-package-mismatch
package armo_builtins

import rego.v1

deny contains msga if {
	template := input[_]
	template.kind == "SandboxTemplate"

	container := template.spec.podTemplate.spec.containers[i]
	not container.resources.limits.cpu

	fixPaths := [{"path": sprintf("spec.podTemplate.spec.containers[%v].resources.limits.cpu", [format_int(i, 10)]), "value": "YOUR_VALUE"}]

	msga := {
		"alertMessage": sprintf("SandboxTemplate '%v' container '%v' does not have CPU limits set.", [template.metadata.name, container.name]),
		"packagename": "armo_builtins",
		"alertScore": 7,
		"failedPaths": [],
		"fixPaths": fixPaths,
		"alertObject": {
			"k8sApiObjects": [template],
		},
	}
}

deny contains msga if {
	template := input[_]
	template.kind == "SandboxTemplate"

	container := template.spec.podTemplate.spec.containers[i]
	cpu_limit := container.resources.limits.cpu

	sandbox_cpu_limit_max := data.postureControlInputs.sandbox_cpu_limit_max[_]
	cpu_to_millicores(cpu_limit) > cpu_to_millicores(sandbox_cpu_limit_max)

	failed_path := sprintf("spec.podTemplate.spec.containers[%v].resources.limits.cpu", [format_int(i, 10)])

	msga := {
		"alertMessage": sprintf("SandboxTemplate '%v' container '%v' CPU limit '%v' exceeds the configured maximum '%v'.", [template.metadata.name, container.name, cpu_limit, sandbox_cpu_limit_max]),
		"packagename": "armo_builtins",
		"alertScore": 7,
		"failedPaths": [failed_path],
		"fixPaths": [],
		"reviewPaths": [failed_path],
		"alertObject": {
			"k8sApiObjects": [template],
		},
	}
}

cpu_to_millicores(q) := n if {
	s := sprintf("%v", [q])
	endswith(s, "m")
	n := to_number(trim_suffix(s, "m"))
} else := n if {
	n := to_number(q) * 1000
}
