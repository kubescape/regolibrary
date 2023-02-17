package armo_builtins

import input.spec as apiservice_spec
import input.metadata.name as api_name
import future.keywords

vulnerable_version = [
  "1.21.14",
  "1.22.0-1.22.13",
  "1.23.0-1.23.10",
  "1.24.0-1.24.4",
  "1.25.0"
]

is_vulnerable = api_name in vulnerable_version

deny[msg] {
  is_vulnerable
  msg := sprintf("API server %s is vulnerable to CVE-2022-3172, an aggregated API server is redirecting client traffic to any URL.", [api_name])
}
