FROM golang:1.22

WORKDIR /app
COPY main.go .
RUN go build -o server main.go

RUN mkdir -p /app/plugins && chmod 777 /app/plugins

EXPOSE 8080 9090
CMD ["./server"]
