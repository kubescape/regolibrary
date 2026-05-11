package armo_builtins

import future.keywords.contains
import future.keywords.if
import future.keywords.in

deny contains msga if {
	deployment := input[_]
	deployment.kind == "Deployment"
	not usable_rolling_update_strategy(deployment.spec.strategy)

	msga := {
		"alertMessage": sprintf("Deployment: %v does not define a usable rolling update strategy", [deployment.metadata.name]),
		"packagename": "armo_builtins",
		"alertScore": 3,
		"reviewPaths": ["spec.strategy"],
		"failedPaths": ["spec.strategy"],
		"fixPaths": [{"path": "spec.strategy", "value": "RollingUpdate strategy with non-zero maxSurge or maxUnavailable"}],
		"alertObject": {"k8sApiObjects": [deployment]},
	}
}

usable_rolling_update_strategy(strategy) if {
	strategy.type == "RollingUpdate"
	usable_rolling_update_value(strategy.rollingUpdate.maxSurge)
}

usable_rolling_update_strategy(strategy) if {
	strategy.type == "RollingUpdate"
	usable_rolling_update_value(strategy.rollingUpdate.maxUnavailable)
}

usable_rolling_update_value(value) if {
	is_number(value)
	value > 0
}

usable_rolling_update_value(value) if {
	is_string(value)
	value != "0"
	value != "0%"
}
