#
# Builder image
FROM registry.suse.com/bci/golang:1.22.7 AS builder

ENV GOPATH=/go
ENV PATH=$PATH:/usr/local/go/bin:$GOPATH/bin

# Build controller
COPY . /src
WORKDIR /src
RUN make

#
# base image
FROM registry.suse.com/bci/bci-micro:15.6@sha256:97d363d79a2e8e20491bb7f5b51bb2db066ad410431bc933f832c9b17bff8f23 AS micro
FROM registry.suse.com/bci/bci-base:15.6@sha256:8e4bd4ffcb3c079924e57cc1264a242746148de118f9cb547cf2149e120a0d87 AS base

ARG TARGETOS
ARG TARGETARCH

COPY --from=micro / /chroot/

# Runtime dependencies
RUN zypper --non-interactive --installroot /chroot --gpg-auto-import-keys install --no-recommends \
    ca-certificates && \
    zypper --non-interactive --installroot /chroot clean -a && \
    rm -rf /chroot/var/log/

FROM micro
ARG VERSION
ARG COMMIT
WORKDIR /
COPY --from=base /chroot/ /
COPY --from=builder /src/stage /

RUN cd /usr/bin/ && rm -rf basename chcon chgrp chmod chown chroot cksum dd df dircolors dirname du install install-info join locale localedef mkdir mkfifo mknod mktemp paste pathchk readlink realpath sync smidiff smidump smilink smiquery smistrip smixlate tee tiemout tload top truncate unlink watch

LABEL name="registry-adapter" \
      vendor="SuSE Security" \
      version=${VERSION} \
      release=${VERSION} \
      neuvector.image="neuvector/registry-adapter" \
      neuvector.role="registry-adapater" \
      neuvector.rev="${COMMIT}"

ENTRYPOINT ["/usr/local/bin/adapter"]
