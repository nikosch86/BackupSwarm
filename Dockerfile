# syntax=docker/dockerfile:1.6

# ---- Build stage ------------------------------------------------------------
FROM golang:1.26-alpine AS build

WORKDIR /src

# Cache modules first
COPY go.mod go.sum ./
RUN go mod download

# Copy sources and build a fully-static binary
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/backupswarm ./cmd/backupswarm

# Pre-create an empty /data directory so the runtime stage can copy it
# with --chown; a fresh named volume mounted at /data inherits this
# ownership on first mount, so containers don't need an init service to
# chown the volume.
RUN mkdir -p /out/data

# ---- Runtime stage ----------------------------------------------------------
FROM gcr.io/distroless/static-debian12:nonroot

COPY --from=build /out/backupswarm /usr/local/bin/backupswarm
COPY --from=build --chown=nonroot:nonroot /out/data /data

USER nonroot:nonroot
WORKDIR /data
VOLUME ["/data"]

ENTRYPOINT ["/usr/local/bin/backupswarm"]
CMD ["--help"]
