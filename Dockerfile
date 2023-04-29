FROM golang:1.19 AS build
WORKDIR /go/src/github.com/codemowers/conntrack-server/
COPY go.mod go.sum ./
RUN go mod download
COPY cmd ./
RUN go build -ldflags "-linkmode 'external' -extldflags '-static'" -o /go/server .

FROM scratch
WORKDIR /
COPY --from=build /go/server /server
ENV GIN_MODE=release
ENTRYPOINT ["/server"]
