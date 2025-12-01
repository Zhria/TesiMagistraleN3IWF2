# Stage 1: Build
FROM golang:1.24-alpine AS builder

RUN apk add --no-cache git

WORKDIR /app
COPY n3iwfCustom .
COPY n3iwfCustom/go.mod n3iwfCustom/go.sum ./

ENV GO111MODULE=on
ENV CGO_ENABLED=0

RUN go mod tidy
RUN go build -o n3iwf ./cmd/main.go
RUN chmod +x n3iwf

FROM alpine:3.19

COPY --from=builder /app/ ./free5gc/n3iwf


