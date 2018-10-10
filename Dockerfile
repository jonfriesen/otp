FROM golang:1.11.1-alpine3.8

LABEL maintainer="Jon Friesen <jon@jonfriesen.ca>"

WORKDIR /go/src/app
COPY . .

RUN go get -d -v ./...
RUN go install -v ./...
RUN CGO_ENABLED=0 GOOS=linux go test -a -installsuffix nocgo -o /app .