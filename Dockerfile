FROM golang:alpine AS builder
WORKDIR $GOPATH/src/github.com/furui/dreamip-go
COPY . .
RUN go build -o /go/bin/dreamip-go


FROM alpine
COPY --from=builder /go/bin/dreamip-go /go/bin/dreamip-go
ENTRYPOINT ["/go/bin/dreamip-go"]
