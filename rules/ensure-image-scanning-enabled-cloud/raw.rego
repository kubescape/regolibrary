package armo_builtins

import rego.v1

# Check if image scanning enabled for EKS
deny contains msga if {
	describe_repositories := input[_]
	describe_repositories.apiVersion == "eks.amazonaws.com/v1"
	describe_repositories.kind == "DescribeRepositories"
	describe_repositories.metadata.provider == "eks"
	repos := describe_repositories.data.Repositories
	some repo in repos
	not image_scanning_configured(repo)

	msga := {
		"alertMessage": "image scanning is not enabled",
		"alertScore": 3,
		"packagename": "armo_builtins",
		"failedPaths": [],
		"fixPaths": [],
		"fixCommand": "aws ecr put-image-scanning-configuration --repository-name $REPO_NAME --image-scanning-configuration scanOnPush=true --region $REGION_CODE",
		"alertObject": {
			"k8sApiObjects": [],
			"externalObjects": describe_repositories,
		},
	}
}

image_scanning_configured(repo) if {
	repo.ImageScanningConfiguration.ScanOnPush == true
}
