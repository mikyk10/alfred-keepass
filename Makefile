PLB=/usr/libexec/PlistBuddy
name=$(shell $(PLB) -c Print:name src/info.plist)
bundleid=$(shell $(PLB) -c Print:bundleid src/info.plist)

# Alfred preferences folder (follows a sync folder if one is set) and the
# installed copy of this workflow inside it, looked up by bundle id.
# Override either on the command line, e.g.
#   make update ALFRED_WORKFLOW_DIR=~/path/to/user.workflow.XXXX
ALFRED_PREFS ?= $(shell plutil -extract current raw -o - "$(HOME)/Library/Application Support/Alfred/prefs.json" 2>/dev/null || echo "$(HOME)/Library/Application Support/Alfred/Alfred.alfredpreferences")
ALFRED_WORKFLOW_DIR ?= $(shell grep -l "<string>$(bundleid)</string>" "$(ALFRED_PREFS)"/workflows/*/info.plist 2>/dev/null | head -1 | xargs -I{} dirname "{}")

all: build open

open: bin/$(name).alfredworkflow
	open bin/$(name).alfredworkflow

build:
	-rm bin/*.alfredworkflow
	-pushd src; v=$$(git describe --tags); $(PLB) -c "Set:version $${v#v}" info.plist; popd
	-pushd src/alkeepass.d; GOOS=darwin GOARCH=amd64 go build -o ../ alkeepass.go; popd
	-pushd src; zip -r ../bin/$(name).alfredworkflow alkeepass icon*.png *.md info.plist; popd


update: build
	@test -n "$(ALFRED_WORKFLOW_DIR)" || { echo "installed workflow not found; set ALFRED_WORKFLOW_DIR" >&2; exit 1; }
	cp -f src/alkeepass "$(ALFRED_WORKFLOW_DIR)/"
	cp -f "$(ALFRED_WORKFLOW_DIR)/info.plist" src/