FROM alpine:latest

RUN mkdir /app

COPY ./bin/authApp /app/
COPY .env.development /app/.env.development

ENV APP_ENV=development

WORKDIR /app

CMD ["/app/authApp"]
