FROM nginx:alpine

COPY crack0x-landing.html /usr/share/nginx/html/index.html

COPY nginx-app.conf /etc/nginx/conf.d/default.conf

EXPOSE 3005