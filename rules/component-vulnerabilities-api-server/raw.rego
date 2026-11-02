# regal ignore:directory-package-mismatch
package armo_builtins

import rego.v1

deny contains msga if {
	some res in input
	res.apiVersion == "componentvulns.kubescape.cloud/v1beta0"
	res.kind == "APIServerVulnerabilities"
	counted_assessment(res)

	failing := [i | some i, v in res.data.vulnerabilities; reportable(v)]
	count(failing) > 0
	vuln_paths := [sprintf("data.vulnerabilities[%d]", [i]) | some i in failing]

	msga := {
		"alertMessage": sprintf("kube-apiserver %v has known vulnerabilities: %v", [res.data.version, concat(", ", [res.data.vulnerabilities[i].id | some i in failing])]),
		"packagename": "armo_builtins",
		"alertScore": 8,
		"reviewPaths": vuln_paths,
		"failedPaths": vuln_paths,
		"fixPaths": [],
		"alertObject": {"k8sApiObjects": [res]},
	}
}

counted_assessment(res) if res.data.assessment == "verified"

counted_assessment(res) if {
	res.data.assessment == "vendor-build"
	enabled("componentVulnCountVendorBuilds")
}

reportable(v) if {
	severity_rank(v.severity) >= min_severity_rank(data.postureControlInputs)
	fix_requirement_met(v)
}

fix_requirement_met(_) if not enabled("componentVulnOnlyWithFix")

fix_requirement_met(v) if v.fixState == "fixed"

enabled(name) if lower(data.postureControlInputs[name][_]) == "true"

severity_rank(s) := object.get(
	{"negligible": 1, "low": 2, "medium": 3, "high": 4, "critical": 5},
	lower(s),
	0,
)

min_severity_rank(inputs) := min(ranks) if {
	ranks := [r | some s in inputs.componentVulnMinSeverity; r := severity_rank(s); r > 0]
	count(ranks) > 0
} else := severity_rank("High")
