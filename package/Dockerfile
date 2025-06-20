#
# Builder image
FROM registry.suse.com/bci/golang:1.24 AS builder
ARG VERSION

ENV GOPATH=/go
ENV PATH=$PATH:/usr/local/go/bin:$GOPATH/bin

COPY config/ /src/config
COPY server/ /src/server
COPY vendor/ /src/vendor
COPY go.mod go.sum adapter.go version.go Makefile /src
WORKDIR /src
RUN sed -i -e 's/interim.*xxxx/'"$VERSION"'/g' ./version.go
RUN make

#
# base image
FROM registry.suse.com/bci/bci-micro:15.6 AS micro
FROM registry.suse.com/bci/bci-base:15.7 AS base
FROM --platform=$BUILDPLATFORM rancher/mirrored-tonistiigi-xx:1.6.1 AS xx
FROM --platform=$BUILDPLATFORM registry.suse.com/bci/bci-base:15.7 AS basebuilder

ARG TARGETPLATFORM
ARG TARGETOS
ARG TARGETARCH

COPY --from=xx / /
COPY --from=micro / /chroot/

RUN echo "[main]" > /etc/zypp/zypp.conf && \
    echo -n "arch = " >> /etc/zypp/zypp.conf && \
    xx-info march >> /etc/zypp/zypp.conf

COPY --from=base /etc/products.d/ /etc/products.d/
COPY --from=base /etc/zypp/ /chroot/etc/zypp/

# Runtime dependencies
RUN zypper refresh && zypper --non-interactive --installroot /chroot install --no-recommends \
    ca-certificates && \
    zypper --non-interactive --installroot /chroot clean -a && \
    rm -rf /chroot/var/log/ /chroot/var/cache/zypp/* /chroot/etc/zypp/

RUN cd /chroot/usr/bin/ && rm -rf basename chcon chgrp chmod chown chroot cksum dd df dircolors dirname du install install-info join locale localedef mkdir mkfifo mknod mktemp paste pathchk readlink realpath sync smidiff smidump smilink smiquery smistrip smixlate tee tiemout tload top truncate unlink watch

RUN mkdir -p /chroot/etc/neuvector/certs/internal/

FROM micro
ARG VERSION
ARG COMMIT
WORKDIR /
COPY --from=basebuilder /chroot/ /
COPY --from=builder /src/stage /

LABEL "name"="registry-adapter" \
      "vendor"="SUSE Security" \
      "neuvector.image"="neuvector/registry-adapter" \
      "neuvector.role"="registry-adapter" \
      "neuvector.rev"="${COMMIT}" \
      "io.artifacthub.package.logo-url"=https://avatars2.githubusercontent.com/u/19367275 \
      "io.artifacthub.package.readme-url"="https://raw.githubusercontent.com/neuvector/registry-adapter/${VERSION}/README.md" \
      "org.opencontainers.image.description"="SUSE Security Registry Adapter" \
      "org.opencontainers.image.title"="SUSE Security Registry Adapter" \
      "org.opencontainers.image.source"="https://github.com/neuvector/registry-adapter/" \
      "org.opencontainers.image.version"="${VERSION}" \
      "org.opensuse.reference"="neuvector/registry-adapter:${VERSION}"
      

ENTRYPOINT ["/usr/local/bin/adapter"]
