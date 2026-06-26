# Stage 1: Build the WayChain binary
FROM golang:1.26 AS builder
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -o /waychain .

# Stage 2: Minimal runtime
FROM alpine:latest
RUN apk add --no-cache ca-certificates
COPY --from=builder /waychain /usr/local/bin/waychain

# Config directory
RUN mkdir -p /etc/waychain

# Default ports
EXPOSE 9001-9005  // P2P
EXPOSE 8545        // RPC

ENTRYPOINT ["waychain"]
CMD ["--help"]