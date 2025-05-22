module github.com/openbao/go-kms-wrapping/wrappers/pkcs11/v2

go 1.23.6

toolchain go1.24.3

replace github.com/openbao/go-kms-wrapping/v2 => ../../

require (
	github.com/ThalesGroup/crypto11 v1.4.1
	github.com/openbao/go-kms-wrapping/v2 v2.2.0
)

require (
	github.com/google/go-cmp v0.6.0 // indirect
	github.com/hashicorp/go-secure-stdlib/parseutil v0.1.9 // indirect
	github.com/hashicorp/go-secure-stdlib/strutil v0.1.2 // indirect
	github.com/hashicorp/go-sockaddr v1.0.6 // indirect
	github.com/hashicorp/go-uuid v1.0.3 // indirect
	github.com/miekg/pkcs11 v1.1.2-0.20231115102856-9078ad6b9d4b // indirect
	github.com/mitchellh/mapstructure v1.5.0 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/ryanuber/go-glob v1.0.0 // indirect
	github.com/thales-e-security/pool v0.0.2 // indirect
	google.golang.org/protobuf v1.36.4 // indirect
)

retract [v2.0.0, v2.0.2]
