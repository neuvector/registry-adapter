ARG BASE_IMAGE_TAG
FROM neuvector/adapter_base:${BASE_IMAGE_TAG}

COPY stage /

LABEL neuvector.image="neuvector/registry-adapter" \
      neuvector.role="registry-adapter" \
      version=${NV_TAG} \
      release=${NV_TAG} \
      neuvector.rev="git.xxxx"

ENTRYPOINT ["/usr/local/bin/adapter"]
