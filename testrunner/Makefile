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

# build and install libgit2
libgit2:
	git submodule update --init --recursive
	cd git2go; make install-static
#	$(CPF) -r git2go$(PSEP)static-build ${GOPATH}$(PSEP)pkg$(PSEP)mod$(PSEP)github.com$(PSEP)libgit2$(PSEP)git2go$(PSEP)v33@v33.0.9$(PSEP)

# go build tags
TAGS = "static"

test:
	go mod tidy
	go test -v -tags=$(TAGS) rego_test.go -run TestAllRules
