FROM alpine:latest

RUN mkdir /app

COPY ./bin/auth-service /app/
COPY .env.development /app/.env.development

ENV APP_ENV=development

WORKDIR /app

CMD ["/app/auth-service"]
