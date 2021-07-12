FROM golang:1.15-alpine
ENV DEBIAN_FRONTEND=noninteractive

RUN mkdir /root/src
ENV GOPATH /root/go
ENV GOROOT /usr/local/go
ENV PATH $PATH:/usr/local/go/bin

RUN apk add --no-cache git mercurial \
    && go get -u github.com/dvyukov/go-fuzz/go-fuzz \
    github.com/dvyukov/go-fuzz/go-fuzz-build \
    github.com/moby/buildkit \
    && apk del git mercurial
#RUN cd $GOPATH/src/github.com/moby/buildkit/util/testutil/fuzz \
#    && $GOPATH/bin/go-fuzz-build && $GOPATH/bin/go-fuzz
