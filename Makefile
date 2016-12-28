all: build
build:
	go build

build_linux:
	gox --osarch linux/amd64

image: build_linux
	docker build -t justinazoff/ssh-auth-logger .
