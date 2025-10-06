A low/zero interaction ssh authentication logging honeypot

## Interesting features

### Structured logging

ssh-auth-logger logs all authentication attempts as json making it easy to
consume in other tools.  No more ugly [openssh log parsing
vulnerabilities](http://dcid.me/texts/attacking-log-analysis-tools.html).

### "Random" host keys

ssh-auth-logger uses HMAC to hash the destination IP address and a key in order to
generate a consistently "random" key for every responding IP address.  This
means you can run ssh-auth-logger on a /16 and every ip address will appear
with a different host key.  TODO: add random sshd version reporting as well.

## Example log entry

This is normally logged on one line

```json
{
  "client_version": "SSH-2.0-libssh2_1.4.3",
  "destinationServicename": "sshd",
  "dpt": "2222",
  "dst": "192.168.1.2",
  "duser": "root",
  "level": "info",
  "msg": "Request with password",
  "password": "P@ssword1",
  "product": "ssh-auth-logger",
  "server_version": "SSH-2.0-OpenSSH_5.3",
  "spt": "38624",
  "src": "192.168.1.4",
  "time": "2017-11-17T19:16:37-05:00"
}
```

## How to use it

```shell
go install github.com/JustinAzoff/ssh-auth-logger@latest
export SSHD_BIND=:2222
~/go/bin/ssh-auth-logger
```

## Note

To bind to port 22 directly:

```shell
sudo setcap cap_net_bind_service=+ep ~/go/bin/ssh-auth-logger
```

## Run with docker

```shell
docker run -t -i --rm  -p 2222:2222 justinazoff/ssh-auth-logger
```

Docker compose example:

```shell
services:
  ssh-auth-logger:
    image: justinazoff/ssh-auth-logger:latest
    container_name: ssh-auth-logger
    environment:
      # Port to listen
      - SSHD_BIND=:2222
    volumes:
      # Mount log file if needed
      - /var/docker/ssh-auth-logger/ssh-auth.log:/var/log/ssh-auth-logger.log
    ports:
     - 2222:2222 # SSH Auth Logger
    restart: unless-stopped
    deploy:
      resources:
        limits:
          cpus: '0.50'
          memory: 100M
    healthcheck:
      test: wget -v localhost:$SSHD_BIND --no-verbose --tries=1 --spider || exit 1
      interval: 5m00s
      timeout: 5s
      retries: 2
      start_period: 5s
    logging:
      driver: json-file
      options:
          max-size: 10m
```
