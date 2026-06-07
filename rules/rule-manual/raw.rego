# regal ignore:directory-package-mismatch  
package armo_builtins

import rego.v1

deny contains {
		"alertMessage": "Please check it manually.",
		"packagename": "armo_builtins",
		"alertScore": 2,
		"failedPaths": [],
		"fixPaths": [],
		"fixCommand": "",
		"alertObject": {"k8sObject": []},
	}
