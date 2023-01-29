.PHONY: test all libgit2

# default task invoked while running make
all: libgit2 test


# Setup cross platform copy command
ifeq ($(OS),Windows_NT)

ifneq ($(strip $(filter %sh,$(basename $(realpath $(SHELL))))),)
POSIXSHELL := 1
else
POSIXSHELL :=
endif

else
# not on windows:
POSIXSHELL := 1

endif

ifneq ($(POSIXSHELL),)

CMDSEP := ;
PSEP := /
CPF := sudo cp -f

else

CMDSEP := &
PSEP := \\
CPF := copy /y

endif


export CGO_ENABLED=1

# go build tags
TAGS = "static"

test:
	go mod tidy
	go test -v -tags=$(TAGS) rego_test.go -run TestAllRules
