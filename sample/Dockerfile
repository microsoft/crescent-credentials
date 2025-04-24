# 
#
#  This Dockerfile is used to build a Docker image for the Crescent credentials project and sample.
#  You can build and run the sample in the container without installing any dependencies on your local machine
#  besides Docker. The browser extension can be installed from the container to your local browser and will 
#  connect to the services running in the container.
#
#  The browser extension files and sample mdl are available in /sample/docker-extension in the project
#  folder after running instantiating the container with 'docker run'.
#
#
#  Build the Docker image (this can take 30 minutes or more and use 35+ GB of disk space):
#
#    # Make sure you are in the root folder of the project even though the Dockerfile is in the sample folder
#    cd crescent-credentials
#
#    # Build the Docker image
#    docker build -f sample/Dockerfile -t crescent-sample .
#
#
#  Run the Docker container:
#
#    A new folder called 'crescent-extension' will be created in the directory where you run the command.
#    This folder will contain the browser extension files and the sample mdl.
#
#    # Windows (Cmd)
#    docker run -v "%cd%\crescent-extension:/extension" -p 8001:8001 -p 8003:8003 -p 8004:8004 crescent-sample
#
#    # Windows (Git Bash)
#    docker run -v "$(pwd -W)\crescent-extension:/extension" -p 8001:8001 -p 8003:8003 -p 8004:8004 crescent-sample
#
#    # Linux
#    docker run -v "$(pwd)/crescent-extension:/extension" -p 8001:8001 -p 8003:8003 -p 8004:8004 crescent-sample
#
# 

FROM rust:slim

SHELL ["/bin/bash", "-c"]

ENV DEBIAN_FRONTEND=noninteractive
ENV ROCKET_ADDRESS=0.0.0.0

RUN apt-get update && apt-get upgrade -y && apt-get clean
RUN apt-get install python3.11-venv python3-pip curl git dos2unix m4 cmake libclang-dev bsdextrautils -y
RUN curl -fsSL https://deb.nodesource.com/setup_lts.x | bash - && apt-get install -y nodejs && node -v && npm -v

# pip requires a virtual environment to not pollute the system python installation
RUN python3 -m venv /venv
ENV PATH="/venv/bin:$PATH"
RUN pip install --upgrade pip
RUN pip install python_jwt git+https://github.com/peppelinux/pyMDOC-CBOR.git

# Install circom
RUN git clone https://github.com/iden3/circom.git && cd circom && git checkout v2.1.6 && cargo build --release && cargo install --path circom;

# Copy local Crescent source code to the container
COPY . /crescent-credentials

# Fix line endings for all shell scripts as we may be copying from Windows
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

WORKDIR /crescent-credentials/ecdsa-pop
RUN cargo build --release

WORKDIR /crescent-credentials/sample
RUN ./setup-sample.sh

# Create run script to start all services and copy extension files to the mount folder
RUN echo '#!/bin/bash' > start-all.sh && \
    echo 'cd client_helper && cargo run --release &' >> start-all.sh && \
    echo 'cd issuer && cargo run --release &' >> start-all.sh && \
    echo 'cd verifier && cargo run --release &' >> start-all.sh && \
    echo 'cp -r /crescent-credentials/sample/client/dist/* /extension/' >> start-all.sh && \
    echo 'cp -r /crescent-credentials/sample/client/mdl.cbor.hex /extension/' >> start-all.sh && \
    echo 'wait -n' >> start-all.sh && \
    chmod +x start-all.sh

EXPOSE 8001 8003 8004

CMD ["./start-all.sh"]

