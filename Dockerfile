FROM golang:1.19-alpine as builder
RUN mkdir /build 
ADD . /build/
WORKDIR /build 
RUN go build -o gortas .

FROM alpine
RUN adduser -S -D -H -h /app appuser
USER appuser
COPY --from=builder /build/gortas /usr/bin/gortas
ADD ./auth-config.yaml /app/config/auth-config.yaml
WORKDIR /app
ENTRYPOINT ["gortas"]
CMD ["--config", "./config/auth-config.yaml"]