FROM ubuntu:latest

RUN apt-get update

ENV PATH="/usr/local/go/bin:${PATH}"

RUN DEBIAN_FRONTEND='noninteractive' apt-get install -y libzmq3-dev \
                        wget \
                        pkg-config \
                        gcc

RUN wget https://golang.org/dl/go1.15.7.linux-amd64.tar.gz ; \
    tar -C /usr/local -xzf go1.15.7.linux-amd64.tar.gz ; \
    rm go1.15.7.linux-amd64.tar.gz

WORKDIR project

COPY . .

RUN go build example/main.go

CMD ["./main"]