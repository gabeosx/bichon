FROM debian:bookworm-slim

ARG CYRUS_SOURCE=cyrus-imapd-3.12.2.tar.gz
ARG CYRUS_SHA256=681ca57483b3dd9ee91f171e11e5ee21684d1da87262e27ea6ff9bd076e9514d

LABEL org.opencontainers.image.version="3.12.2" \
      org.opencontainers.image.source="https://github.com/cyrusimap/cyrus-imapd" \
      bichon.cyrus.source-sha256="681ca57483b3dd9ee91f171e11e5ee21684d1da87262e27ea6ff9bd076e9514d"

COPY ${CYRUS_SOURCE} /tmp/${CYRUS_SOURCE}

RUN set -eu; \
    echo "${CYRUS_SHA256}  /tmp/${CYRUS_SOURCE}" | sha256sum -c -; \
    apt-get update; \
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      autoconf automake bison build-essential flex gosu libical-dev \
      libjansson-dev libkrb5-dev libpcre2-dev libsasl2-dev libsasl2-modules \
      libsqlite3-dev libssl-dev libtool libxml2-dev pkg-config sasl2-bin \
      uuid-dev zlib1g-dev; \
    groupadd --force mail; \
    groupadd --system cyrus; \
    useradd --system --gid cyrus --groups mail --home-dir /var/lib/cyrus \
      --shell /usr/sbin/nologin cyrus; \
    mkdir -p /usr/src/cyrus; \
    tar -xzf /tmp/${CYRUS_SOURCE} -C /usr/src/cyrus --strip-components=1; \
    cd /usr/src/cyrus; \
    ./configure \
      --prefix=/usr/local/cyrus \
      --with-cyrus-user=cyrus \
      --with-sqlite=yes \
      --without-clamav \
      --without-zeroskip \
      --without-chardet \
      --without-cld2 \
      --without-guesstz \
      --without-nghttp2 \
      --without-wslay \
      --without-brotli \
      --without-zstd; \
    make -j2; \
    make install; \
    /usr/local/cyrus/sbin/cyr_buildinfo \
      | grep -Eq '"CYRUS_VERSION"[[:space:]]*:[[:space:]]*"3\.12\.2"'; \
    rm -rf /usr/src/cyrus /tmp/${CYRUS_SOURCE} /var/lib/apt/lists/*

COPY container-entrypoint.sh /usr/local/sbin/bichon-cyrus-entrypoint
RUN chmod 0755 /usr/local/sbin/bichon-cyrus-entrypoint

EXPOSE 143

ENTRYPOINT ["/usr/local/sbin/bichon-cyrus-entrypoint"]
