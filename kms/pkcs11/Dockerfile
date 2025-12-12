FROM docker.io/rust:latest AS kryoptic

RUN apt update && DEBIAN_FRONTEND="noninteractive" apt install -y --no-install-recommends libclang-dev
RUN curl -sL https://github.com/latchset/kryoptic/archive/refs/heads/main.tar.gz | tar xz
RUN cd kryoptic-main && cargo build --release && mv target/release/libkryoptic_pkcs11.so /

FROM docker.io/golang:latest AS tests

RUN apt update && DEBIAN_FRONTEND="noninteractive" apt install -y --no-install-recommends softhsm2
ENV SOFTHSM_PATH=/usr/lib/softhsm/libsofthsm2.so

COPY --from=kryoptic libkryoptic_pkcs11.so /usr/local/lib
ENV KRYOPTIC_PATH=/usr/local/lib/libkryoptic_pkcs11.so

ENV CGO_ENABLED=1

WORKDIR /go-kms-wrapping
COPY ./go.mod ./go.sum ./

WORKDIR /go-kms-wrapping/kms/pkcs11
COPY ./kms/pkcs11/go.mod ./kms/pkcs11/go.sum ./

RUN go mod download
COPY . /go-kms-wrapping

ARG TESTFLAGS=-v
RUN go test ${TESTFLAGS} ./...
