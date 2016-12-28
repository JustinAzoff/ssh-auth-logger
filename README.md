## How to use it

    go get -u -v github.com/JustinAzoff/ssh-auth-logger
    $GOPATH/bin/ssh-auth-logger

## Note

To bind to port 22 directly:

    setcap cap_net_bind_service=+ep $GOPATH/bin/ssh-auth-logger

