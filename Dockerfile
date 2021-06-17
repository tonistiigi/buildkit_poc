# syntax = docker/dockerfile:1.2

ARG RUNC_VERSION=v1.0.0-rc95
ARG CONTAINERD_VERSION=v1.5.2
# containerd v1.4 for integration tests
ARG CONTAINERD_ALT_VERSION=v1.4.6
# available targets: buildkitd, buildkitd.oci_only, buildkitd.containerd_only
ARG BUILDKIT_TARGET=buildkitd
ARG REGISTRY_VERSION=2.7.1
ARG ROOTLESSKIT_VERSION=v0.14.2
ARG CNI_VERSION=v0.9.1
ARG SHADOW_VERSION=4.8.1
ARG FUSEOVERLAYFS_VERSION=v1.5.0
ARG STARGZ_SNAPSHOTTER_VERSION=v0.5.0

ARG ALPINE_VERSION=3.12

# git stage is used for checking out remote repository sources
FROM --platform=$BUILDPLATFORM alpine:${ALPINE_VERSION} AS git
RUN apk add --no-cache git

# xx is a helper for cross-compilation
FROM --platform=$BUILDPLATFORM tonistiigi/xx@sha256:810dc54d5144f133a218e88e319184bf8b9ce01d37d46ddb37573e90decd9eef AS xx

# gobuild is base stage for compiling go/cgo
FROM --platform=$BUILDPLATFORM golang:1.17beta1-alpine AS gobuild-base
RUN apk add --no-cache file bash clang lld pkgconfig git make
COPY --from=xx / /

# runc source
FROM git AS runc-src
ARG RUNC_VERSION
WORKDIR /usr/src
RUN git clone https://github.com/opencontainers/runc.git runc \
  && cd runc && git checkout -q "$RUNC_VERSION"

# build runc binary
FROM gobuild-base AS runc
WORKDIR $GOPATH/src/github.com/opencontainers/runc
ARG TARGETPLATFORM
# gcc is only installed for libgcc
# lld has issues building static binaries for ppc so prefer ld for it
RUN set -e; xx-apk add musl-dev gcc libseccomp-dev libseccomp-static; \
  [ "$(xx-info arch)" != "ppc64le" ] || XX_CC_PREFER_LINKER=ld xx-clang --setup-target-triple
RUN --mount=from=runc-src,src=/usr/src/runc,target=. --mount=target=/root/.cache,type=cache \
  CGO_ENABLED=1 xx-go build -mod=vendor -ldflags '-extldflags -static' -tags 'apparmor seccomp netgo cgo static_build osusergo' -o /usr/bin/runc ./ && \
  xx-verify --static /usr/bin/runc

FROM gobuild-base AS buildkit-base
WORKDIR /src
ENV GOFLAGS=-mod=vendor

# scan the version/revision info
FROM buildkit-base AS buildkit-version
# TODO: PKG should be inferred from go modules
RUN --mount=target=. \
  PKG=github.com/moby/buildkit VERSION=$(git describe --match 'v[0-9]*' --dirty='.m' --always --tags) REVISION=$(git rev-parse HEAD)$(if ! git diff --no-ext-diff --quiet --exit-code; then echo .m; fi); \
  echo "-X ${PKG}/version.Version=${VERSION} -X ${PKG}/version.Revision=${REVISION} -X ${PKG}/version.Package=${PKG}" | tee /tmp/.ldflags; \
  echo -n "${VERSION}" | tee /tmp/.version;

# build buildctl binary
FROM buildkit-base AS buildctl
ENV CGO_ENABLED=0
ARG TARGETPLATFORM
RUN --mount=target=. --mount=target=/root/.cache,type=cache \
  --mount=target=/go/pkg/mod,type=cache \
  --mount=source=/tmp/.ldflags,target=/tmp/.ldflags,from=buildkit-version \
  xx-go build -ldflags "$(cat /tmp/.ldflags)" -o /usr/bin/buildctl ./cmd/buildctl && \
  xx-verify --static /usr/bin/buildctl

# build buildkitd binary
FROM buildkit-base AS buildkitd
ARG BUILDKITD_TAGS
ARG TARGETPLATFORM
RUN --mount=target=. --mount=target=/root/.cache,type=cache \
  --mount=target=/go/pkg/mod,type=cache \
  --mount=source=/tmp/.ldflags,target=/tmp/.ldflags,from=buildkit-version \
  CGO_ENABLED=0 xx-go build -ldflags "$(cat /tmp/.ldflags) -extldflags '-static'" -tags "osusergo netgo static_build seccomp ${BUILDKITD_TAGS}" -o /usr/bin/buildkitd ./cmd/buildkitd && \
  xx-verify --static /usr/bin/buildkitd

FROM scratch AS binaries-linux-helper
COPY --from=runc /usr/bin/runc /buildkit-runc
# built from https://github.com/tonistiigi/binfmt/runs/1743699129
COPY --from=tonistiigi/binfmt:buildkit@sha256:75583ce1cf4a7166fd2592f45e4ff3f53727eee6edcd3a3e804f749b1f214a39 / /
FROM binaries-linux-helper AS binaries-linux
COPY --from=buildctl /usr/bin/buildctl /
COPY --from=buildkitd /usr/bin/buildkitd /

FROM scratch AS binaries-darwin
COPY --from=buildctl /usr/bin/buildctl /

FROM scratch AS binaries-windows
COPY --from=buildctl /usr/bin/buildctl /buildctl.exe

FROM binaries-$TARGETOS AS binaries

FROM --platform=$BUILDPLATFORM alpine:${ALPINE_VERSION} AS releaser
RUN apk add --no-cache tar gzip
WORKDIR /work
ARG TARGETPLATFORM
RUN --mount=from=binaries \
  --mount=source=/tmp/.version,target=/tmp/.version,from=buildkit-version \
  mkdir -p /out && tar czvf "/out/buildkit-$(cat /tmp/.version).$(echo $TARGETPLATFORM | sed 's/\//-/g').tar.gz" --mtime='2015-10-21 00:00Z' --sort=name --transform 's/^./bin/' .

FROM scratch AS release
COPY --from=releaser /out/ /

FROM alpine:${ALPINE_VERSION} AS buildkit-export
# nsswitch.conf needs to be present to work around
#   https://github.com/golang/go/issues/35305
# drop this once we start building with Go 1.16
RUN apk add --no-cache fuse3 git openssh pigz xz \
  && ln -s fusermount3 /usr/bin/fusermount \
  && echo "hosts: files dns" >/etc/nsswitch.conf
COPY examples/buildctl-daemonless/buildctl-daemonless.sh /usr/bin/
VOLUME /var/lib/buildkit

FROM git AS containerd-src
ARG CONTAINERD_VERSION
ARG CONTAINERD_ALT_VERSION
WORKDIR /usr/src
RUN git clone https://github.com/containerd/containerd.git containerd

FROM gobuild-base AS containerd-base
WORKDIR /go/src/github.com/containerd/containerd
ARG TARGETPLATFORM
ENV CGO_ENABLED=1 BUILDTAGS=no_btrfs
RUN xx-apk add musl-dev gcc && xx-go --wrap

FROM containerd-base AS containerd
ARG CONTAINERD_VERSION
RUN --mount=from=containerd-src,src=/usr/src/containerd,readwrite --mount=target=/root/.cache,type=cache \
  git fetch origin \
  && git checkout -q "$CONTAINERD_VERSION" \
  && make bin/containerd \
  && make bin/containerd-shim-runc-v2 \
  && make bin/ctr \
  && mv bin /out

# containerd v1.4 for integration tests
FROM containerd-base as containerd-alt
ARG CONTAINERD_ALT_VERSION
ARG GO111MODULE=off
RUN --mount=from=containerd-src,src=/usr/src/containerd,readwrite --mount=target=/root/.cache,type=cache \
  git fetch origin \
  && git checkout -q "$CONTAINERD_ALT_VERSION" \
  && make bin/containerd \
  && make bin/containerd-shim-runc-v2 \
  && mv bin /out

ARG REGISTRY_VERSION
FROM registry:$REGISTRY_VERSION AS registry

FROM gobuild-base AS rootlesskit
ARG ROOTLESSKIT_VERSION
RUN git clone https://github.com/rootless-containers/rootlesskit.git /go/src/github.com/rootless-containers/rootlesskit
WORKDIR /go/src/github.com/rootless-containers/rootlesskit
ARG TARGETPLATFORM
RUN  --mount=target=/root/.cache,type=cache \
  git checkout -q "$ROOTLESSKIT_VERSION"  && \
  CGO_ENABLED=0 xx-go build -o /rootlesskit ./cmd/rootlesskit && \
  xx-verify --static /rootlesskit

FROM gobuild-base AS stargz-snapshotter
ARG STARGZ_SNAPSHOTTER_VERSION
RUN git clone https://github.com/containerd/stargz-snapshotter.git /go/src/github.com/containerd/stargz-snapshotter
WORKDIR /go/src/github.com/containerd/stargz-snapshotter
ARG TARGETPLATFORM
RUN --mount=target=/root/.cache,type=cache \
  git checkout -q "$STARGZ_SNAPSHOTTER_VERSION" && \
  xx-go --wrap && \
  mkdir /out && CGO_ENABLED=0 PREFIX=/out/ make && \
  xx-verify --static /out/containerd-stargz-grpc && \
  xx-verify --static /out/ctr-remote

FROM --platform=$BUILDPLATFORM alpine:${ALPINE_VERSION} AS fuse-overlayfs
RUN apk add --no-cache curl
COPY --from=xx / /
ARG FUSEOVERLAYFS_VERSION
ARG TARGETPLATFORM
RUN mkdir /out && \
  curl -sSL -o /out/fuse-overlayfs https://github.com/containers/fuse-overlayfs/releases/download/${FUSEOVERLAYFS_VERSION}/fuse-overlayfs-$(xx-info march) && \
  chmod +x /out/fuse-overlayfs && \
  xx-verify --static /out/fuse-overlayfs

# Copy together all binaries needed for oci worker mode
FROM buildkit-export AS buildkit-buildkitd.oci_only
COPY --from=buildkitd.oci_only /usr/bin/buildkitd.oci_only /usr/bin/
COPY --from=buildctl /usr/bin/buildctl /usr/bin/
ENTRYPOINT ["buildkitd.oci_only"]

# Copy together all binaries for containerd worker mode
FROM buildkit-export AS buildkit-buildkitd.containerd_only
COPY --from=buildkitd.containerd_only /usr/bin/buildkitd.containerd_only /usr/bin/
COPY --from=buildctl /usr/bin/buildctl /usr/bin/
ENTRYPOINT ["buildkitd.containerd_only"]

# Copy together all binaries for oci+containerd mode
FROM buildkit-export AS buildkit-buildkitd-linux
COPY --from=binaries / /usr/bin/
ENTRYPOINT ["buildkitd"]

FROM binaries AS buildkit-buildkitd-darwin

FROM binaries AS buildkit-buildkitd-windows
# this is not in binaries-windows because it is not intended for release yet, just CI
COPY --from=buildkitd /usr/bin/buildkitd /buildkitd.exe

FROM buildkit-buildkitd-$TARGETOS AS buildkit-buildkitd

FROM alpine:${ALPINE_VERSION} AS containerd-runtime
COPY --from=runc /usr/bin/runc /usr/bin/
COPY --from=containerd /out/containerd* /usr/bin/
COPY --from=containerd /out/ctr /usr/bin/
VOLUME /var/lib/containerd
VOLUME /run/containerd
ENTRYPOINT ["containerd"]

FROM --platform=$BUILDPLATFORM alpine:${ALPINE_VERSION} AS cni-plugins
RUN apk add --no-cache curl
ARG CNI_VERSION
ARG TARGETOS
ARG TARGETARCH
WORKDIR /opt/cni/bin
RUN curl -Ls https://github.com/containernetworking/plugins/releases/download/$CNI_VERSION/cni-plugins-$TARGETOS-$TARGETARCH-$CNI_VERSION.tgz | tar xzv

FROM buildkit-base AS integration-tests-base
ENV BUILDKIT_INTEGRATION_ROOTLESS_IDPAIR="1000:1000"
RUN apk add --no-cache shadow shadow-uidmap sudo vim iptables fuse \
  && useradd --create-home --home-dir /home/user --uid 1000 -s /bin/sh user \
  && echo "XDG_RUNTIME_DIR=/run/user/1000; export XDG_RUNTIME_DIR" >> /home/user/.profile \
  && mkdir -m 0700 -p /run/user/1000 \
  && chown -R user /run/user/1000 /home/user \
  && ln -s /sbin/iptables-legacy /usr/bin/iptables \
  && xx-go --wrap
# musl is needed to directly use the registry binary that is built on alpine
ENV BUILDKIT_INTEGRATION_CONTAINERD_EXTRA="containerd-1.4=/opt/containerd-alt/bin"
ENV BUILDKIT_INTEGRATION_SNAPSHOTTER=stargz
ENV CGO_ENABLED=0
COPY --from=stargz-snapshotter /out/* /usr/bin/
COPY --from=rootlesskit /rootlesskit /usr/bin/
COPY --from=containerd-alt /out/containerd* /opt/containerd-alt/bin/
COPY --from=registry /bin/registry /usr/bin
COPY --from=runc /usr/bin/runc /usr/bin
COPY --from=containerd /out/containerd* /usr/bin/
COPY --from=cni-plugins /opt/cni/bin/bridge /opt/cni/bin/host-local /opt/cni/bin/loopback /opt/cni/bin/
COPY hack/fixtures/cni.json /etc/buildkit/cni.json
COPY --from=binaries / /usr/bin/

FROM integration-tests-base AS integration-tests
COPY . .
ENV BUILDKIT_RUN_NETWORK_INTEGRATION_TESTS=1 BUILDKIT_CNI_INIT_LOCK_PATH=/run/buildkit_cni_bridge.lock

FROM integration-tests AS dev-env
VOLUME /var/lib/buildkit

# newuidmap & newgidmap binaries (shadow-uidmap 4.7-r1) shipped with alpine cannot be executed without CAP_SYS_ADMIN,
# because the binaries are built without libcap-dev.
# So we need to build the binaries with libcap enabled.
FROM --platform=$BUILDPLATFORM alpine:${ALPINE_VERSION} AS idmap
RUN apk add --no-cache git autoconf automake clang lld gettext-dev libtool make byacc binutils
COPY --from=xx / /
ARG SHADOW_VERSION
RUN git clone https://github.com/shadow-maint/shadow.git /shadow && cd /shadow && git checkout $SHADOW_VERSION
WORKDIR /shadow
ARG TARGETPLATFORM
RUN xx-apk add --no-cache musl-dev gcc libcap-dev
RUN CC=$(xx-clang --print-target-triple)-clang ./autogen.sh --disable-nls --disable-man --without-audit --without-selinux --without-acl --without-attr --without-tcb --without-nscd --host $(xx-clang --print-target-triple) \
  && make -j $(nproc) \
  && xx-verify src/newuidmap src/newuidmap \
  && cp src/newuidmap src/newgidmap /usr/bin

# Rootless mode.
FROM alpine:${ALPINE_VERSION} AS rootless
RUN apk add --no-cache fuse3 git openssh pigz xz
COPY --from=idmap /usr/bin/newuidmap /usr/bin/newuidmap
COPY --from=idmap /usr/bin/newgidmap /usr/bin/newgidmap
COPY --from=fuse-overlayfs /out/fuse-overlayfs /usr/bin/
# we could just set CAP_SETUID filecap rather than `chmod u+s`, but requires kernel >= 4.14
# nsswitch.conf needs to be present to work around
#   https://github.com/golang/go/issues/35305
# drop this once we start building with Go 1.16
RUN chmod u+s /usr/bin/newuidmap /usr/bin/newgidmap \
  && adduser -D -u 1000 user \
  && mkdir -p /run/user/1000 /home/user/.local/tmp /home/user/.local/share/buildkit \
  && chown -R user /run/user/1000 /home/user \
  && echo user:100000:65536 | tee /etc/subuid | tee /etc/subgid \
  && echo "hosts: files dns" >/etc/nsswitch.conf
COPY --from=rootlesskit /rootlesskit /usr/bin/
COPY --from=binaries / /usr/bin/
COPY examples/buildctl-daemonless/buildctl-daemonless.sh /usr/bin/
# Kubernetes runAsNonRoot requires USER to be numeric
USER 1000:1000
ENV HOME /home/user
ENV USER user
ENV XDG_RUNTIME_DIR=/run/user/1000
ENV TMPDIR=/home/user/.local/tmp
ENV BUILDKIT_HOST=unix:///run/user/1000/buildkit/buildkitd.sock
VOLUME /home/user/.local/share/buildkit
ENTRYPOINT ["rootlesskit", "buildkitd"]


FROM buildkit-${BUILDKIT_TARGET}


