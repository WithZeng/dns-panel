FROM golang:1.26-alpine AS builder

WORKDIR /build
RUN apk add --no-cache gcc musl-dev

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=1 go build -o dns-panel -ldflags="-s -w" .

FROM alpine:latest

RUN apk add --no-cache ca-certificates tzdata curl

WORKDIR /app
COPY --from=builder /build/dns-panel .
COPY --from=builder /build/templates ./templates
COPY --from=builder /build/static ./static

RUN mkdir -p /app/data

EXPOSE 5000

CMD ["./dns-panel"]
