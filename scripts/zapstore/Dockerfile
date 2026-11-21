# zsp, Zapstore's publishing tool, which only ships for macOS and Linux:
# its Linux build in a small Debian image, checked against the SHA-256 that
# zapstore.dev publishes, plus git (zsp reads the source repository with it).
# Built by scripts/zapstore.ps1.
FROM debian:bookworm-slim

ARG ZSP_VERSION=2.0.1
ARG ZSP_SHA256=1ef5373f8ecd9ba63d2c3fab98abb0d31b2244a2aac31b3749fb205c7d5f5b38

RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates curl git socat \
 && curl -fsSL -o /usr/local/bin/zsp \
      "https://github.com/zapstore/zsp/releases/download/v${ZSP_VERSION}/zsp-${ZSP_VERSION}-linux-amd64" \
 && echo "${ZSP_SHA256}  /usr/local/bin/zsp" | sha256sum -c - \
 && chmod +x /usr/local/bin/zsp \
 && apt-get purge -y curl && apt-get autoremove -y && rm -rf /var/lib/apt/lists/*

# zsp's preview page (with the button that approves a publish) listens on
# 127.0.0.1:17008 inside the container only; socat makes it reachable on
# 17009, which zapstore.ps1 maps to 127.0.0.1:17008 on the PC
RUN printf '#!/bin/sh\nsocat TCP-LISTEN:17009,fork,reuseaddr,bind=0.0.0.0 TCP:127.0.0.1:17008 2>/dev/null &\nexec zsp "$@"\n' > /usr/local/bin/zsp-run \
 && chmod +x /usr/local/bin/zsp-run

WORKDIR /src
ENTRYPOINT ["zsp-run"]
