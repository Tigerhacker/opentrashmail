FROM webdevops/php-nginx:7.4-alpine

ENV WEB_DOCUMENT_INDEX=index.html
EXPOSE 25

WORKDIR /app
VOLUME /data
ADD . /app/.
