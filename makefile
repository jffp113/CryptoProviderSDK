.DEFAULT_GOAL := build

build:
	go build keygen.go

clear:
	rm keygen