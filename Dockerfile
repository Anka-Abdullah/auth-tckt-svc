# Build stage dengan versi spesifik
FROM golang:1.25.5-alpine AS builder

WORKDIR /app

# Install dependencies dengan versi yang diketahui
RUN apk add --no-cache git gcc musl-dev

# Copy go mod files
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY . .

# Build the application
RUN CGO_ENABLED=0 GOOS=linux go build -o main ./cmd/api/main.go

# Runtime stage dengan versi spesifik
FROM alpine:3.19.1

WORKDIR /root/

# Install CA certificates untuk HTTPS
RUN apk --no-cache add ca-certificates

# Copy binary dari builder
COPY --from=builder /app/main .

# Copy environment file untuk docker
COPY .env.docker .env

# Expose port
EXPOSE 8080

# Run the application
CMD ["./main"]