# ---------------------------
# Stage 1: Base PHP + Apache
# ---------------------------
FROM php:8.2-apache AS base

# Install system dependencies
RUN apt-get update && apt-get install -y \
    curl \
    unzip \
    git \
    libpng-dev \
    libjpeg-dev \
    libfreetype6-dev \
    && docker-php-ext-configure gd --with-freetype --with-jpeg \
    && docker-php-ext-install -j$(nproc) pdo pdo_mysql gd \
    && rm -rf /var/lib/apt/lists/*

# Enable Apache modules
RUN a2enmod rewrite headers expires

# ---------------------------
# Stage 2: Copy Application
# ---------------------------
WORKDIR /var/www/html

# Copy app source
COPY . /var/www/html/

# Set permissions
RUN chown -R www-data:www-data /var/www/html \
    && chmod -R 755 /var/www/html

# Apache config for .htaccess support + fix ServerName warning
RUN { \
    echo 'ServerName localhost'; \
    echo '<Directory /var/www/html/>'; \
    echo '    AllowOverride All'; \
    echo '    Require all granted'; \
    echo '</Directory>'; \
} > /etc/apache2/conf-available/app.conf \
  && a2enconf app.conf

# ---------------------------
# Stage 3: Production Settings
# ---------------------------

# PHP settings (override defaults)
RUN { \
    echo "expose_php=0"; \
    echo "display_errors=Off"; \
    echo "log_errors=On"; \
    echo "upload_max_filesize=20M"; \
    echo "post_max_size=25M"; \
    echo "memory_limit=256M"; \
    echo "max_execution_time=60"; \
} > /usr/local/etc/php/conf.d/app.ini

# ---------------------------
# Stage 4: Expose & Run
# ---------------------------

# Apache default listens on 80, we remap to 8080 for Koyeb
EXPOSE 8080

# Update Apache to listen on 8080 instead of 80
RUN sed -i 's/80/8080/g' /etc/apache2/ports.conf /etc/apache2/sites-available/000-default.conf

CMD ["apache2-foreground"]
