# Certbot & Docker/Nginx quick commands (example)
# 1) Ensure DNS A record points to your server IP for tu-dominio.com
# 2) Start nginx container (or install nginx on host) serving port 80
# 3) Run certbot (host) or use certbot docker image to obtain certs:
sudo certbot certonly --standalone -d tu-dominio.com --email admin@tu-dominio.com --agree-tos --non-interactive
# or using docker certbot (example):
docker run --rm -v $(pwd)/letsencrypt:/etc/letsencrypt -p 80:80 certbot/certbot certonly --standalone -d tu-dominio.com --email admin@tu-dominio.com --agree-tos --non-interactive
# After obtaining certs, mount them into nginx and restart nginx.
