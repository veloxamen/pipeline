# syntax=docker/dockerfile:1
FROM golang:1.22-bookworm AS builder
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build -trimpath -ldflags="-s -w" \
    -o /out/network-trigger ./cmd/network-trigger

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=builder /out/network-trigger /network-trigger
EXPOSE 8080
ENTRYPOINT ["/network-trigger"]
