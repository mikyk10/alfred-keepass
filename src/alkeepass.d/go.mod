module alkeepass

go 1.26.0

require (
	github.com/pkg/errors v0.9.1
	github.com/spf13/cobra v1.3.0
	github.com/stretchr/testify v1.12.1
	github.com/tobischo/gokeepasslib/v3 v3.7.1
	golang.org/x/text v0.43.0
)

require (
	github.com/inconshreveable/mousetrap v1.0.0 // indirect
	github.com/spf13/pflag v1.0.5 // indirect
	github.com/tobischo/argon2 v0.2.0 // indirect
	go.yaml.in/yaml/v3 v3.0.5 // indirect
	golang.org/x/crypto v0.58.0 // indirect
	golang.org/x/sys v0.49.0 // indirect
)

replace github.com/tobischo/gokeepasslib/v3 => ../../../gokeepasslib
