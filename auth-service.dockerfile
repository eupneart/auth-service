FROM alpine:latest

RUN mkdir /app

COPY ./bin/authApp /app

COPY .env /app/.env

CMD [ "/app/authApp" ]
