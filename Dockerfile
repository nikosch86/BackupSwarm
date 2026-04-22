# syntax=docker/dockerfile:1.6

# ---- Build stage ------------------------------------------------------------
FROM golang:1.24-alpine AS build

WORKDIR /src

# Cache modules first
COPY go.mod go.sum ./
RUN go mod download

# Copy sources and build a fully-static binary
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/backupswarm ./cmd/backupswarm

# ---- Runtime stage ----------------------------------------------------------
FROM gcr.io/distroless/static-debian12:nonroot

COPY --from=build /out/backupswarm /usr/local/bin/backupswarm

USER nonroot:nonroot
WORKDIR /data
VOLUME ["/data"]

ENTRYPOINT ["/usr/local/bin/backupswarm"]
CMD ["--help"]
