# syntax=docker/dockerfile:1
# Stage 1: build
FROM golang:1.22-bookworm AS builder
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build -trimpath -ldflags="-s -w" \
    -o /out/decrypt-job ./cmd/decrypt-job

# Stage 2: minimal runtime image
# Use distroless for a minimal attack surface — no shell, no package manager.
FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=builder /out/decrypt-job /decrypt-job
ENTRYPOINT ["/decrypt-job"]
