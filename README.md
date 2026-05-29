# SSH Auth Logger

A low/zero interaction ssh authentication logging honeypot

## Interesting features

### Structured logging

ssh-auth-logger logs all authentication attempts as json making it easy to consume in other tools.  No more ugly [openssh log parsing vulnerabilities](http://dcid.me/texts/attacking-log-analysis-tools.html).

### "Random" host keys

ssh-auth-logger uses HMAC to hash the destination IP address and a key in order to generate a consistently "random" key for every responding IP address.  This means you can run ssh-auth-logger on a /16 and every ip address will appear with a different host key. Random sshd version reporting as well.

### Example log entry

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
  "server_version": "SSH-2.0-dropbear_2019.78",
  "server_key_type":"ssh-rsa",
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

Bind to port 2222 in a host machine

```shell
docker run -t -i --rm  -p 2222:2222 justinazoff/ssh-auth-logger
```

Docker compose example:

```yaml
# Create isolated network
networks:
  isolated_net:
    driver: bridge

services:
  ssh-auth-logger:
    image: justinazoff/ssh-auth-logger:latest
    container_name: ssh-auth-logger
    environment:
      - TZ=Europe/Berlin                      # You can set Time Zone to see logs with your local time
      # Following are default values
      # SSHD Part
#      - SSHD_RATE=320                         # bits per second, emulate very slow connection
#      - SSHD_BIND=:2222                       # Port and interface sshd to listen
#      - SSHD_KEY_KEY="Take me to your leader" # It's a secret key that is used to generate a deterministic hash value for a given host IP address
#      - SSHD_MAX_AUTH_TRIES=6                 # The minimum number of authentication attempts allowed
#      - SSHD_RSA_BITS=3072                    # If you use 'rsa' you can also set RSA key size, 2048, 3072, 4096 (very rare)
#      - SSHD_PROFILE_SCOPE=host               # Can be 'remote_ip' (each remote IP gets its own profile, simulating per-attacker behavior.), or anything else for 'host' (the same local host always gets the same profile, e.g. binding to 0.0.0.0:22 will always select the same Profile).
#      - SSHD_SEND_BANNER=false                # Send SSH Login Banner before Password prompt
#      - SSHD_LOG_CLEAR_PASSWORD=true          # Log Passwords as clear text or Base64 coded
#      - SSHD_LOGS_FILTER=""                   # Comma-separated list of allowed fields. 'msg', 'level' and 'time' can't be removed. Following combinations are possible: "duser,src,spt,dst,dpt,client_version,server_version,password,keytype,fingerprint,server_key_type,destinationServicename,product"
      # Telnet Part
#      - TELNET_BIND=:2323                     # Port and interface telnetd to listen
#      - TELNET_LOG_CLEAR_PASSWORD=true        # Log Passwords as clear text or Base64 coded
#      - TELNET_RATE=20                        # bits per second, emulate very slow connection
    volumes:
      # Mount log file if needed
      - /var/docker/ssh-auth-logger/log:/var/log
    ports:
     - 2222:2222 # SSH Auth Logger
     - 2323:2323 # SSH Auth Logger Telnet
    networks:
      # Use isolated docker network, so that other containers will be not reachable from it
      - isolated_net
    restart: unless-stopped
    deploy:
      resources:
        limits:
          cpus: '0.50'
          memory: 100M
    healthcheck:
      # Will test if port is still open AND log file was not vanished by host machine log rotate
      test: pgrep ssh-auth-logger && test -s /var/log/ssh-auth-logger.log || exit 1
      interval: 5m00s
      timeout: 5s
      retries: 2
      start_period: 5s
    logging:
      driver: json-file
      options:
          max-size: 10m
```

## fail2ban configuration

To configure [fail2ban](https://github.com/fail2ban/fail2ban) you have to create a filter:

```shell
sudo nano /etc/fail2ban/filter.d/ssh-auth-logger.local
```

with following content:

```shell
[Definition]
_daemon = ssh-auth-logger

# Match JSON log line with a "time", "msg" fields and a "src" IP
failregex = ^.*"msg":"Request with (password|key)".*"src":"<HOST>".*$
            ^.*"msg":"Telnet login attempt".*"src":"<HOST>".*$

datepattern = %%Y-%%m-%%dT%%H:%%M:%%S(?:Z|%%z)

ignoreregex =
```

The you have to update your `jail.local`:

```shell
sudo nano /etc/fail2ban/jail.local
```

with following config:

```shell
[ssh-auth-honeypot]
enabled = true
filter = ssh-auth-logger
action = iptables-allports
         # Additonally you can setup abuseipdb reporting as per https://github.com/fail2ban/fail2ban/blob/master/config/action.d/abuseipdb.conf
         #abuseipdb[abuseipdb_category="18,22"]
# Docker mount log to the localsystem
logpath = /var/docker/ssh-auth-logger/log/ssh-auth-logger.log
# maxretry should be equal or more than in a SSHD_MAX_AUTH_TRIES
maxretry = 6
# For very slow attacker that tries 3 passwords per day
findtime = 1d
# Ban time can be anything you like
bantime = 1d
```

After that you have to reload your fail2ban with command:

```shell
sudo fail2ban-client reload
```
