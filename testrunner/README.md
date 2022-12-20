# Test-Runner for Rego Rules
This package tests the OPA Rego rules.

# Running the tests
First you need to [setup the environment](#environment-setup). Then run

```
go test -v -tags=static rego_test.go -run TestAllRules
```
Or
```
make test
```

# Environment setup
The Test Runner depends on [kubescape](https://github.com/kubescape/kubescape). As such, it depends also on [git2go](https://github.com/libgit2/git2go). In order to compile and run the tests properly you will have to build git2go.

## Linux/MacOS
Install libgit2 dependency
   
```
make libgit2
```

> `cmake` is required to build libgit2. You can install it by running `sudo apt-get install cmake` (Linux) or `brew install cmake` (macOS)

## Windows
1. Download and install MSYS64 (can be found at [MSYS2 website](https://www.msys2.org/))
2. Add `C:\msys64\mingw64\bin` to the `PATH` environment variable
3. Install build packages
    ```
    C:\MSYS64\usr\bin\pacman -S --needed --noconfirm make
    C:\MSYS64\usr\bin\pacman -S --needed --noconfirm mingw-w64-x86_64-cmake
    C:\MSYS64\usr\bin\pacman -S --needed --noconfirm mingw-w64-x86_64-gcc
    C:\MSYS64\usr\bin\pacman -S --needed --noconfirm mingw-w64-x86_64-pkg-config
    C:\MSYS64\usr\bin\pacman -S --needed --noconfirm msys2-w32api-runtime
    ```

4. Install libgit2 kubescape dependency
   
    ```
    path=C:\MSYS64\usr\bin;%path%
    make libgit2
    ```

## Troubleshooting

* if running with `git2go` is causing problems, you may need to run: 
```
go clean --cache
go clean -modcache
```
Notice - This command deletes the cache downloaded along with unpacked code dependencies.

This will affect build performance the next time.

# VS code configuration samples

You can use the sample files below to setup your VS code environment for debugging purposes.

```json5
// .vscode/settings.json
{
    "go.testTags": "static",
    "go.toolsEnvVars": {
        "CGO_ENABLED": "1"
    }
}
```
```json5
// .vscode/launch.json
{
    "name": "Launch test function",
    "type": "go",
    "request": "launch",
    "mode": "test",
    "program": "${workspaceFolder}/rego_test.go",
    "buildFlags": "-tags=static",
    "args": [
        "-test.run",
        "TestAllRules"
    ]
}
```

# Adding new rules


When adding a new rule, create a test for it.  
All tests are run upon pushing, please make sure they all pass.    
This mechanism will aggregate resources accordingly, and get the default config inputs as input automatically.  
Currently, tests compare the `k8sApiObjects`, `externalObjects`, `failedPaths`, and `RuleStatus` fields.  
To run all tests:  `cd testrunner/ && go test -v rego_test.go -run TestAllRules`

## How to create a test
<br />

1 - Browse into `rule-tests` directory.  
2 - Create a new folder with the same name as the rule to be tested  
3 - Inside this folder, create a new folder for your test (arbitrary name), and browse into it    
4 - Create a file name `expected.json` and put the expected response  
5 - Create a folder name `input` and put the files which are the input for the test (yaml/json)  
6 - That's it. The test will run using the rego and metadata.json from the `rules` file, using what's inside the `input` folder as input

You can create as many tests as you wish

## Debugging your tests
<br />

Inside the `rego_test.go` file, in the `testrunner` directory, you can run tests from a specific directory using the `TestSingleRule` function. Just change the variable `dir` to the name of your test folder.
<br />  
For running a single regoe locally, you can use the `TestSingleRego` function. It will take as input the files inside the `input` folder, in the `test-single-rego` directory. Just change the `testDir` variable to the name of your test. The result will be printed.  
So no more need for rego playground, and this is especially helpful when using aggregation