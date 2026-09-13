FROM php:8.2-apache

RUN a2enmod rewrite
RUN docker-php-ext-install openssl 2>/dev/null || true

RUN mkdir -p /var/www/html/uploads && \
    chown -R www-data:www-data /var/www/html/uploads && \
    chmod 777 /var/www/html/uploads

COPY index.php /var/www/html/index.php

EXPOSE 80
