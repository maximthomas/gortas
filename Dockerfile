FROM golang:alpine as builder
RUN mkdir /build 
ADD . /build/
WORKDIR /build 
RUN go build -o main .

FROM alpine
RUN adduser -S -D -H -h /app appuser
USER appuser
COPY --from=builder /build/main /app/
ADD ./auth-config.yaml /app/config/auth-config.yaml
WORKDIR /app
CMD ["./main", "--config", "./config/auth-config.yaml"]