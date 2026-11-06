FROM sshhardener_integration-debian:latest
# Intentionally omit fail2ban and python3-systemd: the production preparation step
# must install them on a fresh Debian 12 server. No host service/cgroup mount is used.
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends systemd iproute2 sshpass && rm -rf /var/lib/apt/lists/*
ENTRYPOINT ["/bin/sh"]
