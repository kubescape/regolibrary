package armo_builtins

import input.spec as apiservice_spec
import input.metadata.name as api_name
import future.keywords

vulnerable_version {
  ver := ["1.21.14", "1.22.0-1.22.13", "1.23.0-1.23.10", "1.24.0-1.24.4", "1.25.0"]
  ver[_] = api_name
}

deny[msg] {
  vulnerable_version
  msg := sprintf("API server %s is vulnerable to CVE-2022-3172, an aggregated API server is redirecting client traffic to any URL.", [api_name])
}
