# ---------- Stage 1: Build ----------
FROM golang:1.25.3-alpine AS builder

# Install build tools
RUN apk add --no-cache git

# Set working directory
WORKDIR /app

# Copy go mod files first (for caching)
COPY go.mod go.sum ./
RUN go mod download

# Copy the rest of the source
COPY . .

# Build the binary
RUN go build -o authentio ./cmd/server


# ---------- Stage 2: Run ----------
FROM alpine:latest

WORKDIR /root/

# Add CA certs for HTTPS requests
RUN apk --no-cache add ca-certificates

# Copy the binary from the builder
COPY --from=builder /app/authentio .

# Expose port
EXPOSE 8080

# Start the app
CMD ["./authentio"]
