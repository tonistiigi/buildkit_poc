# syntax=docker/dockerfile:1.2

# protoc is dynamically linked to glibc to can't use golang:1.10-alpine
FROM golang:1.17beta1-buster AS gobuild-base
# https://github.com/golang/protobuf/blob/v1.3.5/.travis.yml#L15
ARG PROTOC_VERSION=3.11.4
ARG GOGO_VERSION=v1.3.2
RUN apt-get update && apt-get --no-install-recommends install -y \
	unzip \
	&& true

ARG TARGETOS TARGETARCH
RUN set -e; \
	arch=$(echo $TARGETARCH | sed -e s/amd64/x86_64/ -e s/arm64/aarch_64/); \
	wget -q https://github.com/google/protobuf/releases/download/v${PROTOC_VERSION}/protoc-${PROTOC_VERSION}-${TARGETOS}-${arch}.zip && unzip protoc-${PROTOC_VERSION}-${TARGETOS}-${arch}.zip -d /usr/local

RUN git clone https://github.com/gogo/protobuf.git /go/src/github.com/gogo/protobuf \
	&& cd /go/src/github.com/gogo/protobuf \
	&& git checkout -q $GOGO_VERSION \
	&& go install ./protoc-gen-gogo ./protoc-gen-gogofaster ./protoc-gen-gogoslick

ARG PROTOBUF_VERSION=v1.3.5
RUN git clone https://github.com/golang/protobuf.git /go/src/github.com/golang/protobuf \
	&& cd /go/src/github.com/golang/protobuf \
	&& git checkout -q $PROTOBUF_VERSION \
	&& go install ./protoc-gen-go

WORKDIR /go/src/github.com/moby/buildkit

# Generate into a subdirectory because if it is in the root then the
# extraction with `docker export` ends up putting `.dockerenv`, `dev`,
# `sys` and `proc` into the source directory. With this we can use
# `tar --strip-components=1 generated-files` on the output of `docker
# export`.
FROM gobuild-base AS generated
RUN mkdir /generated-files
RUN --mount=target=/tmp/src \
	cp -r /tmp/src/. . && \
	git add -A && \
	go generate -mod=vendor -v ./... && \
	git ls-files -m --others -- **/*.pb.go | tar -cf - --files-from - | tar -C /generated-files -xf -

FROM scratch AS update
COPY --from=generated /generated-files /generated-files

FROM gobuild-base AS validate
RUN --mount=target=/tmp/src \
	cp -r /tmp/src/. . && \
	go generate -mod=vendor -v ./... && git diff && ./hack/validate-generated-files check
