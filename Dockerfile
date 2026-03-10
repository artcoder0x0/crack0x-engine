FROM node:20-alpine

RUN apk add --no-cache nginx

# ── Landing page (nginx on port 3005) ────────────────────────────────────
COPY crack0x-landing.html /usr/share/nginx/html/index.html
COPY nginx-app.conf /etc/nginx/conf.d/default.conf

# ── Admin server (node on port 3006) ─────────────────────────────────────
WORKDIR /app
COPY admin-server.js .
COPY admin-dashboard.html .
COPY package.json .
RUN npm install

COPY start.sh /start.sh
RUN chmod +x /start.sh

EXPOSE 3005
EXPOSE 3006

CMD ["/start.sh"]