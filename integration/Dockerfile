FROM ubuntu:24.04
ENV container=docker
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends systemd systemd-sysv dbus ca-certificates openssl jq && rm -rf /var/lib/apt/lists/*
COPY bin/derper-go /opt/derper-go
COPY integration/systemd.sh /opt/systemd-test.sh
RUN chmod 0755 /opt/derper-go /opt/systemd-test.sh && touch /opt/derper-go-isolated-test
STOPSIGNAL SIGRTMIN+3
CMD ["/sbin/init"]
