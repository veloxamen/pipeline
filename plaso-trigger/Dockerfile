# syntax=docker/dockerfile:1
FROM golang:1.22-bookworm AS builder
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build -trimpath -ldflags="-s -w" \
    -o /out/plaso-trigger ./cmd/plaso-trigger

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=builder /out/plaso-trigger /plaso-trigger
EXPOSE 8080
ENTRYPOINT ["/plaso-trigger"]
