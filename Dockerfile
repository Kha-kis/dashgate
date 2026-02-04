# Build stage
FROM golang:1.24-alpine AS builder

# Install build dependencies for CGO (required by go-sqlite3)
RUN apk add --no-cache gcc musl-dev

WORKDIR /build

# Version injected at build time
ARG VERSION=dev

# Copy go mod files first for caching
COPY go.mod go.sum ./
RUN go mod download

# Copy source
COPY main.go .
COPY internal/ ./internal/

# Build with CGO enabled for sqlite3
RUN --mount=type=cache,target=/root/.cache/go-build \
    --mount=type=cache,target=/go/pkg/mod \
    CGO_ENABLED=1 GOOS=linux go build -ldflags="-s -w -X main.Version=${VERSION#v}" -o dashgate .

# Runtime stage
FROM alpine:3.21

RUN apk --no-cache add ca-certificates su-exec && \
    adduser -D -u 1000 dashgate && \
    mkdir -p /config/icons && chown -R dashgate:dashgate /config

WORKDIR /app

COPY --from=builder /build/dashgate .
COPY templates/ /app/templates/
COPY static/ /app/static/
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 1738

HEALTHCHECK --interval=30s --timeout=5s --retries=3 CMD wget -qO- http://localhost:1738/health || exit 1

ENTRYPOINT ["/entrypoint.sh"]
CMD ["./dashgate"]
