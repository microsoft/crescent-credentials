FROM ubuntu:22.04

SHELL ["/bin/bash", "-c"]

ENV DEBIAN_FRONTEND=noninteractive
ENV ROCKET_ADDRESS=0.0.0.0

RUN apt-get update && apt-get upgrade -y && apt-get clean
RUN apt-get install git curl software-properties-common build-essential python3-pip cmake clang libclang-dev llvm-dev m4 bsdextrautils dos2unix -y
# RUN { add-apt-repository ppa:git-core/ppa -y; apt update; apt install git -y; git --version; }
RUN curl -fsSL https://deb.nodesource.com/setup_lts.x | bash - && apt-get install -y nodejs && node -v && npm -v
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | bash -s -- -y
ENV PATH=/root/.cargo/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
RUN pip install --upgrade pip setuptools wheel setuptools-scm
RUN pip install python_jwt git+https://github.com/peppelinux/pyMDOC-CBOR.git

RUN git clone https://github.com/iden3/circom.git && cd circom && git checkout v2.1.6 && cargo build --release && cargo install --path circom;
COPY . /crescent-credentials
RUN find /crescent-credentials -type f -name "*.sh" -exec dos2unix {} +

WORKDIR /crescent-credentials
RUN git submodule update --init --recursive;

WORKDIR /crescent-credentials/circuit_setup/scripts

RUN ./run_setup.sh rs256
RUN ./run_setup.sh rs256-sd
RUN ./run_setup.sh rs256-db
RUN ./run_setup.sh mdl1

WORKDIR /crescent-credentials/creds
RUN cargo run --bin crescent --release --features print-trace zksetup --name rs256
RUN cargo run --bin crescent --release --features print-trace prove --name rs256
RUN cargo run --bin crescent --release --features print-trace show --name rs256
RUN cargo run --bin crescent --release --features print-trace verify --name rs256

RUN cargo run --bin crescent --release --features print-trace zksetup --name rs256-sd
RUN cargo run --bin crescent --release --features print-trace prove --name rs256-sd
RUN cargo run --bin crescent --release --features print-trace show --name rs256-sd
RUN cargo run --bin crescent --release --features print-trace verify --name rs256-sd

RUN cargo run --bin crescent --release --features print-trace zksetup --name rs256-db
RUN cargo run --bin crescent --release --features print-trace prove --name rs256-db
RUN cargo run --bin crescent --release --features print-trace show --name rs256-db
RUN cargo run --bin crescent --release --features print-trace verify --name rs256-db

RUN cargo run --bin crescent --release --features print-trace zksetup --name mdl1
RUN cargo run --bin crescent --release --features print-trace prove --name mdl1
RUN cargo run --bin crescent --release --features print-trace show --name mdl1
RUN cargo run --bin crescent --release --features print-trace verify --name mdl1

WORKDIR /crescent-credentials/sample
RUN ./setup-sample.sh
RUN echo '#!/bin/bash' > start-all.sh && \
    # echo 'cd setup_service && cargo run --release &' >> start-all.sh && \
    echo 'cd client_helper && cargo run --release &' >> start-all.sh && \
    echo 'cd issuer && cargo run --release &' >> start-all.sh && \
    echo 'cd verifier && cargo run --release &' >> start-all.sh && \
    echo 'cp -r /crescent-credentials/sample/client/dist/* /crescent-credentials/sample/client/extension/' >> start-all.sh && \
    echo 'cp -r /crescent-credentials/sample/client/mdl.cbor.hex /crescent-credentials/sample/client/extension/' >> start-all.sh && \
    echo 'wait -n' >> start-all.sh && \
    chmod +x start-all.sh

EXPOSE 8001 8003 8004

CMD ["./start-all.sh"]

# Run with the following commands:
#   cd crescent-credentials
#   docker build -f sample/Dockerfile -t crescent-sample .
#   docker run -v "$(pwd -W)\docker-extension:/crescent-credentials/sample/client/extension" -p 8001:8001 -p 8003:8003 -p 8004:8004 crescent-sample

# docker run -v "D:\Repos-Temp\crescent-credentials-docker\sample\client\dist:/crescent-credentials/sample/client/extension" -p 8001:8001 -p 8003:8003 -p 8004:8004 crescent-sample
