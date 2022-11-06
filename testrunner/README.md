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