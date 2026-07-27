FROM golang:1.23-alpine AS builder
WORKDIR /app
COPY yyb_go .
RUN go mod download
RUN CGO_ENABLED=0 GOOS=linux \
    go build -o yyb-go ./cmd/yyb-go

FROM alpine
WORKDIR /app
COPY --from=builder /app/yyb-go .
EXPOSE 8000

CMD ["./yyb-go", "-host", "0.0.0.0", "-port", "8000"]
