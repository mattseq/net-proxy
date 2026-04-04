# Stage 1: Build
FROM rust:alpine AS builder
WORKDIR /app
COPY . .
RUN cargo build --release

# Stage 2: Run
FROM alpine:latest
RUN apk add --no-cache iproute2 iptables
WORKDIR /app
# Copy the binary from the builder stage
COPY --from=builder /app/target/release/server /app/server
CMD ["./server"]