FROM ubuntu:20.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && \
    apt-get install -y nginx mono-fastcgi-server4 mono-devel && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY web.config /app/web.config
COPY index.aspx /app/index.aspx
COPY upload.aspx /app/upload.aspx
COPY nginx.conf /etc/nginx/sites-available/default

RUN mkdir -p /app/uploads && chmod 777 /app/uploads
RUN mkdir -p /app/bin

EXPOSE 80

COPY start.sh /start.sh
RUN chmod +x /start.sh

CMD ["/start.sh"]
