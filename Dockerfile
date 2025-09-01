FROM php:8.2-apache

# Install PDO MySQL
RUN docker-php-ext-install pdo pdo_mysql

# Copy app
COPY . /var/www/html/

# Enable mod_rewrite
RUN a2enmod rewrite

# Apache config for .htaccess
RUN echo '<Directory /var/www/html>\n\
    AllowOverride All\n\
    </Directory>' > /etc/apache2/conf-available/rewrite.conf && \
    a2enconf rewrite

EXPOSE 8080
CMD ["apache2-foreground"]
