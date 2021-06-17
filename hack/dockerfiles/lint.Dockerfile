# syntax=docker/dockerfile:1.2

FROM golang:1.17beta1-alpine
RUN apk add --no-cache gcc musl-dev yamllint
RUN wget -O- -nv https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | sh -s v1.39.0
WORKDIR /go/src/github.com/moby/buildkit
RUN --mount=target=/go/src/github.com/moby/buildkit --mount=target=/root/.cache,type=cache \
  golangci-lint run
RUN --mount=target=/go/src/github.com/moby/buildkit --mount=target=/root/.cache,type=cache \
  yamllint -c .yamllint.yml --strict .
