FROM debian:12-slim
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends openssh-server openssh-client sudo systemd python3 python3-paramiko libpam-google-authenticator && rm -rf /var/lib/apt/lists/*
ENTRYPOINT ["/bin/sh"]
