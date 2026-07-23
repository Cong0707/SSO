FROM node:22-alpine AS web-builder
WORKDIR /src/web
COPY web/package.json web/package-lock.json ./
RUN npm ci
COPY web/ ./
RUN npm run build

FROM golang:1.26.5-alpine AS api-builder
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . ./
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/sso ./cmd/sso
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/sso-migrate ./cmd/migrate
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/sso-migrate-new-api ./cmd/migrate-new-api

FROM alpine:3.22
RUN apk add --no-cache ca-certificates tzdata \
    && addgroup -g 10001 -S sso \
    && adduser -u 10001 -S -D -H -G sso sso
WORKDIR /app
COPY --from=api-builder /out/sso /app/sso
COPY --from=api-builder /out/sso-migrate /app/sso-migrate
COPY --from=api-builder /out/sso-migrate-new-api /app/sso-migrate-new-api
COPY --from=web-builder /src/web/dist /app/web/dist
RUN mkdir -p /app/data && chown -R sso:sso /app
USER 10001:10001
ENV SSO_ADDR=:8080 \
    SSO_ISSUER=http://127.0.0.1:8080 \
    SSO_DATABASE_DRIVER=postgres \
    SSO_DATABASE_DSN="host=127.0.0.1 user=sso password=change-me dbname=sso port=5432 sslmode=disable TimeZone=UTC" \
    SSO_DATA_DIR=/app/data \
    SSO_MASTER_KEY_FILE=/app/data/master.key \
    SSO_OIDC_SIGNING_KEY_FILE=/app/data/oidc-signing.pem \
    SSO_ALLOW_KEY_GENERATION=false \
    SSO_WEB_DIR=/app/web/dist
EXPOSE 8080
VOLUME ["/app/data"]
ENTRYPOINT ["/app/sso"]
