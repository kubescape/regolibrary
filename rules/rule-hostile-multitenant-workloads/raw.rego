package armo_builtins

import rego.v1

deny contains msga if {
	msga := {
		"alertMessage": "Please check it manually.",
		"packagename": "armo_builtins",
		"alertScore": 2,
		"fixPaths": [],
		"failedPaths": [],
		"alertObject": {},
	}
}
