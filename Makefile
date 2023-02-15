PLB=/usr/libexec/PlistBuddy
name=$(shell $(PLB) -c Print:name src/info.plist)

all: build open

open: bin/$(name).alfredworkflow
	open bin/$(name).alfredworkflow

build:
	-rm bin/*.alfredworkflow
	-pushd src; v=$$(git describe --tags); $(PLB) -c "Set:version $${v#v}" info.plist; popd
	-pushd src/alkeepass.d; GOOS=darwin GOARCH=amd64 go build -o ../ alkeepass.go; popd
	-pushd src; zip -r ../bin/$(name).alfredworkflow alkeepass icon*.png *.md info.plist; popd