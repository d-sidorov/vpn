FROM golang:1.26-alpine AS build

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/veil ./cmd/veil

FROM alpine:3.22

COPY --from=build /out/veil /usr/local/bin/veil
COPY docker/entrypoint.sh /entrypoint.sh
RUN chmod 755 /usr/local/bin/veil /entrypoint.sh

EXPOSE 80 443
ENTRYPOINT ["/entrypoint.sh"]
