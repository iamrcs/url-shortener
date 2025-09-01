# Use official PHP Apache image
FROM php:8.2-apache

# Enable Apache mod_rewrite
RUN a2enmod rewrite

# Copy app files into container
COPY . /var/www/html/

# Set working directory
WORKDIR /var/www/html/

# Install PDO and PostgreSQL driver
RUN docker-php-ext-install pdo pdo_pgsql

# Expose port 8080 for Koyeb
EXPOSE 8080

# Tell Apache to listen on 8080 instead of 80
RUN sed -i 's/80/8080/g' /etc/apache2/sites-available/000-default.conf \
    && sed -i 's/80/8080/g' /etc/apache2/ports.conf

CMD ["apache2-foreground"]
