FROM python:3.8-slim-bullseye

# bullseye is EOL on deb.debian.org; repoint apt at the archive
RUN sed -i \
    -e 's|deb.debian.org/debian-security|archive.debian.org/debian-security|g' \
    -e 's|deb.debian.org/debian|archive.debian.org/debian|g' \
    -e '/-updates/d' \
    /etc/apt/sources.list \
    && echo 'Acquire::Check-Valid-Until "false";' > /etc/apt/apt.conf.d/99no-check-valid

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libgmp-dev \
    libssl-dev \
    flex \
    bison \
    m4 \
    wget \
    git \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# PBC 0.5.14 (pairing-based cryptography library, charm-crypto's native dependency)
RUN wget -q https://crypto.stanford.edu/pbc/files/pbc-0.5.14.tar.gz \
    && tar -xzf pbc-0.5.14.tar.gz \
    && cd pbc-0.5.14 \
    && ./configure \
    && make \
    && make install \
    && ldconfig \
    && cd .. \
    && rm -rf pbc-0.5.14 pbc-0.5.14.tar.gz

# charm-crypto (BSW07 CP-ABE), built from source
RUN git clone --depth 1 https://github.com/JHUISI/charm.git \
    && cd charm \
    && ./configure.sh \
    && make \
    && make install \
    && cd .. \
    && rm -rf charm

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

CMD ["uvicorn", "backend.app.main:app", "--host", "0.0.0.0", "--port", "8000", "--reload"]
