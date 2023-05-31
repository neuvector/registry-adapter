ARG BASE_IMAGE_TAG
FROM neuvector/adapter_base:${BASE_IMAGE_TAG}

COPY stage /

LABEL neuvector.image="neuvector/registry-adapter" \
      neuvector.role="registry-adapter"

ENTRYPOINT ["/usr/local/bin/adapter"]
