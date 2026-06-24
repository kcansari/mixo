  FROM golang:1.26.4-alpine AS builder

  WORKDIR /app

  COPY go.mod go.sum ./
  RUN go mod download

  COPY . .

  RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o server ./cmd

  FROM alpine:3.22

  RUN addgroup -S app && adduser -S app -G app

  WORKDIR /app

  COPY --from=builder /app/server ./server

  USER app

  EXPOSE 8080

  CMD ["./server"]