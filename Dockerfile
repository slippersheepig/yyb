FROM golang:1.23-alpine AS builder
WORKDIR /app
COPY yyb_go .
RUN go mod download
RUN CGO_ENABLED=0 \
    go build -o yyb-go ./cmd/yyb-go

FROM alpine
WORKDIR /app
COPY --from=builder /app/yyb-go .
COPY yyb_go/resource ./resource
EXPOSE 8000

CMD ["./yyb-go", "-host", "0.0.0.0", "-port", "8000"]
