package armo_builtins

import future.keywords.contains
import future.keywords.if

deny contains msga if {
	deployment := input[_]
	deployment.kind == "Deployment"
	strategy_type := deployment.spec.strategy.type
	not usable_rolling_update_strategy(strategy_type)

	msga := {
		"alertMessage": sprintf("Deployment: %v does not use a rolling update strategy", [deployment.metadata.name]),
		"packagename": "armo_builtins",
		"alertScore": 3,
		"reviewPaths": ["spec.strategy.type"],
		"failedPaths": ["spec.strategy.type"],
		"fixPaths": [{"path": "spec.strategy.type", "value": "RollingUpdate"}],
		"alertObject": {"k8sApiObjects": [deployment]},
	}
}

usable_rolling_update_strategy(strategy_type) if {
	usable_rolling_update_value(strategy_type)
}

usable_rolling_update_value(strategy_type) if {
	strategy_type == "RollingUpdate"
}
