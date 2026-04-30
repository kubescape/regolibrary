# Regolibrary Search & Navigation Guide

This guide explains how to effectively search and navigate the regolibrary codebase.

## Codebase Structure

The regolibrary follows a hierarchical structure:

```
regolibrary/
├── frameworks/          # 13 framework definitions (JSON)
│   └── *.json          # Framework files (e.g., cis-v1.10.0.json, armobest.json)
├── controls/            # 262 control definitions (JSON)
│   └── *.json          # Control files that group related rules
├── rules/              # 347 Rego policy rules
│   └── <rule-name>/    # Each rule has its own directory
│       ├── raw.rego           # Main policy logic
│       ├── filter.rego        # Optional filter logic
│       ├── rule.metadata.json # Rule metadata and configuration
│       └── test/              # Test cases
│           └── <test-name>/
│               ├── input/     # Test input files
│               └── expected.json
├── scripts/            # Utility scripts for managing the library
└── testrunner/         # Testing infrastructure
```

## Effective Search Strategies

### 1. Search by Rule Name
When you know the rule name, search for it directly:
- "How does the workload-with-cluster-takeover-roles rule work?"
- "What does the drop-capability-netraw rule check?"

### 2. Search by Control ID or Name
Search for controls that contain specific rules:
- "What rules are in control C-0061?"
- "How does the 'Pods in default namespace' control work?"

### 3. Search by Framework
Find controls and rules within a framework:
- "What controls are in the CIS framework?"
- "Show me the NSA framework controls"

### 4. Search by Kubernetes Resource Type
Find rules that check specific resources:
- "What rules check Pod security contexts?"
- "Find rules that validate RoleBinding configurations"

### 5. Search by Security Concern
Search by the security issue being addressed:
- "How do we detect privileged containers?"
- "What rules check for exposed services?"
- "Find rules that validate RBAC permissions"

### 6. Search by Rego Pattern
When looking for specific Rego code patterns:
- "How do rules check for privileged containers in Rego?"
- "Show examples of rules that use deny statements"

## Key File Patterns

### Rule Files
- `raw.rego` - Contains the main policy logic using Rego
- `filter.rego` - Optional filter to determine which resources are evaluated
- `rule.metadata.json` - Defines:
  - `match` - Which Kubernetes resources this rule applies to
  - `description` - What the rule checks
  - `remediation` - How to fix violations
  - `ruleQuery` - Usually "armo_builtins"

### Control Files
- Located in `controls/*.json`
- Contains:
  - `name` - Control name
  - `controlID` - Unique identifier (e.g., "C-0061")
  - `rulesNames` - List of rule names this control includes
  - `description` - What the control checks
  - `category` - Control category (Workload, Configuration, etc.)

### Framework Files
- Located in `frameworks/*.json`
- Contains:
  - `name` - Framework name
  - `controlsNames` - List of control names included
  - `scanningScope` - When this framework applies (cluster, file, cloud, etc.)

## Common Search Examples

### Finding a Rule by Functionality
**Query**: "Find rules that check for containers running as root"
**Expected**: Rules like `run-as-non-root`, `run-as-user`, etc.

### Understanding a Control
**Query**: "What does control C-0061 check and which rules does it use?"
**Expected**: Control metadata and its associated rules

### Finding Similar Rules
**Query**: "Show me all rules that check for privileged containers"
**Expected**: Multiple rules with similar security checks

### Understanding Framework Structure
**Query**: "What controls are included in the CIS Kubernetes benchmark?"
**Expected**: List of controls in the CIS framework

## Tips for Effective Navigation

1. **Start with frameworks** - If you know the framework (CIS, NSA, etc.), start there
2. **Use control IDs** - Controls are often referenced by ID (C-XXXX)
3. **Check rule metadata first** - `rule.metadata.json` gives you the overview
4. **Look at test cases** - Test cases in `test/` directories show expected behavior
5. **Use semantic search** - Ask questions in natural language rather than exact file names

## File Counts

- **347 Rego files** - Policy rules written in Rego
- **262 Control files** - Control definitions
- **13 Framework files** - Framework definitions
- **~1200+ Test cases** - Test scenarios for rules

## Quick Reference

### Rule Structure
```rego
package armo_builtins

deny[msga] {
    # Policy logic here
    msga := {
        "alertMessage": "...",
        "packagename": "armo_builtins",
        "alertScore": <number>,
        "alertObject": {...},
        "failedPaths": "...",
        "fixPaths": [...]
    }
}
```

### Control Structure
```json
{
    "name": "Control Name",
    "controlID": "C-XXXX",
    "rulesNames": ["rule-name-1", "rule-name-2"],
    "description": "...",
    "remediation": "..."
}
```

### Framework Structure
```json
{
    "name": "FrameworkName",
    "controlsNames": ["Control Name 1", "Control Name 2"],
    "scanningScope": {
        "matches": ["cluster", "file"]
    }
}
```
