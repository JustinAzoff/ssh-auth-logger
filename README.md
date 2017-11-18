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

```
{
  "client_version": "SSH-2.0-libssh2_1.4.3",
  "destinationServicename": "sshd",
  "dpt": "22",
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

    go get -u -v github.com/JustinAzoff/ssh-auth-logger
    export SSHD_BIND=:2222
    ~/go/bin/ssh-auth-logger

## Note

To bind to port 22 directly:

    sudo setcap cap_net_bind_service=+ep ~/go/bin/ssh-auth-logger

## Run with docker

    docker run -t -i --rm  -p 2222:22 justinazoff/ssh-auth-logger
