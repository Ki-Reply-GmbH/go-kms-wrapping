FROM docker.io/rust:latest AS kryoptic
RUN apt update && DEBIAN_FRONTEND="noninteractive" apt install -y --no-install-recommends libclang-dev
WORKDIR /kryoptic
RUN curl -fL https://github.com/latchset/kryoptic/archive/53ebd3cd929e6503cfa353f94679646d74ceeb30.tar.gz \
	| tar xz -C . --strip-components=1
RUN cargo build --release

FROM docker.io/golang:latest AS env
ENV SOFTHSM_PATH=/usr/lib/softhsm/libsofthsm2.so
RUN apt update && DEBIAN_FRONTEND="noninteractive" apt install -y --no-install-recommends softhsm2
ENV KRYOPTIC_PATH=/usr/local/lib/libkryoptic_pkcs11.so
COPY --from=kryoptic /kryoptic/target/release/libkryoptic_pkcs11.so ${KRYOPTIC_PATH}

FROM env AS test
ENV CGO_ENABLED=1
WORKDIR /go-kms-wrapping
COPY ./go.mod ./go.sum ./
WORKDIR /go-kms-wrapping/kms/pkcs11
COPY ./kms/pkcs11/go.mod ./kms/pkcs11/go.sum ./
RUN go mod download
COPY . /go-kms-wrapping
ARG TESTFLAGS=-v
RUN go test ${TESTFLAGS} ./...
