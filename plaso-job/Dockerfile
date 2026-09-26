# syntax=docker/dockerfile:1

# Stage 1: build the Go orchestrator binary.
FROM golang:1.22-bookworm AS builder
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build -trimpath -ldflags="-s -w" \
    -o /out/plaso-job ./cmd/plaso-job

# Stage 2: the official Plaso image already has psteal.py, log2timeline,
# psort, and all their parser dependencies (Python, dfVFS, etc.) on PATH —
# that's the whole point of building on top of it rather than reinstalling
# Plaso ourselves. We just add our Go orchestrator binary.
FROM log2timeline/plaso:latest
COPY --from=builder /out/plaso-job /usr/local/bin/plaso-job
ENTRYPOINT ["/usr/local/bin/plaso-job"]
