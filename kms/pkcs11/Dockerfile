FROM docker.io/golang:latest

RUN apt update && \
	DEBIAN_FRONTEND="noninteractive" apt install -y --no-install-recommends softhsm2 opensc
RUN sed -i 's/log.level = ERROR/log.level = DEBUG/' /etc/softhsm/softhsm2.conf

WORKDIR /go-kms-wrapping
COPY ./go.mod ./go.sum ./

WORKDIR /go-kms-wrapping/kms/pkcs11
COPY ./kms/pkcs11/go.mod ./kms/pkcs11/go.sum ./

RUN go mod download

COPY . /go-kms-wrapping

RUN <<EOF
  set -eux

  # TODO(satoqz): Set up testing sandbox via SoftHSM.
EOF

RUN go test -v -race
