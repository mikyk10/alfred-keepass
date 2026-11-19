module alkeepass

go 1.27.4

require (
	github.com/pkg/errors v0.9.1
	github.com/spf13/cobra v1.10.2
	github.com/stretchr/testify v1.12.1
	github.com/tobischo/gokeepasslib/v3 v3.7.1
	golang.org/x/sys v0.50.0
	golang.org/x/text v0.44.0
)

require (
	github.com/inconshreveable/mousetrap v1.1.0 // indirect
	github.com/spf13/pflag v1.1.0 // indirect
	github.com/tobischo/argon2 v0.2.0 // indirect
	go.yaml.in/yaml/v3 v3.0.6 // indirect
	golang.org/x/crypto v0.59.0 // indirect
)

replace github.com/tobischo/gokeepasslib/v3 => github.com/mikyk10/gokeepasslib/v3 v3.0.0-20261118080207-5f94ceb9be3b
