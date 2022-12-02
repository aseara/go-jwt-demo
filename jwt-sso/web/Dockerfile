FROM node:18.12 as builder
WORKDIR /web
COPY . .

RUN npm i && npm run build

FROM nginx:alpine
COPY --from=builder /web/dist /usr/share/nginx/html
COPY --from=builder /web/nginx.conf /etc/nginx/conf.d/default.conf