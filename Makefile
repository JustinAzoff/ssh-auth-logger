all: sync build
sync:
	govendor sync
build:
	go build

build_linux:
	gox --osarch linux/amd64

check_docker:
	@docker ps > /dev/null

image: check_docker build_linux
	docker build -t justinazoff/ssh-auth-logger .

push_image: image
	docker push justinazoff/ssh-auth-logger
