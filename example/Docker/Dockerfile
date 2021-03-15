FROM ubuntu:latest

RUN apt-get update

ENV PATH="/usr/local/go/bin:${PATH}"

RUN DEBIAN_FRONTEND='noninteractive' apt-get install -y libzmq3-dev \
                        wget \
                        pkg-config \
                        gcc \
                        git

RUN wget https://golang.org/dl/go1.15.7.linux-amd64.tar.gz ; \
    tar -C /usr/local -xzf go1.15.7.linux-amd64.tar.gz ; \
    rm go1.15.7.linux-amd64.tar.gz

RUN git config --global url."https://jffp113:d635c14a90e10ab8ddbf3a09a8ef8c16507ea08e@github.com".insteadOf https://github.com

WORKDIR project

COPY . .

RUN go build example/main.go

CMD ["./main"]