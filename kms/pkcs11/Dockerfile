FROM docker.io/fedora:rawhide

RUN dnf update -y && dnf install -y golang opensc softhsm kryoptic

ENV CGO_ENABLED=1

ENV SOFTHSM_LIBRARY_PATH=/usr/lib64/pkcs11/libsofthsm2.so
ENV KRYOPTIC_LIBRARY_PATH=/usr/lib64/pkcs11/libkryoptic_pkcs11.so

ENV SOFTHSM_TESTS=1

WORKDIR /go-kms-wrapping
COPY ./go.mod ./go.sum ./

WORKDIR /go-kms-wrapping/kms/pkcs11
COPY ./kms/pkcs11/go.mod ./kms/pkcs11/go.sum ./

RUN go mod download

ARG TESTFLAGS=-v

COPY . /go-kms-wrapping
RUN go test ${TESTFLAGS} -run ./...
