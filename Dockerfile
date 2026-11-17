FROM node:22-alpine AS frontend
WORKDIR /src/frontend
COPY frontend/package*.json ./
RUN npm ci
COPY frontend/ ./
RUN npm run build

FROM golang:1.24-alpine AS backend
WORKDIR /src
ARG GOPROXY=https://goproxy.cn,direct
ENV GOPROXY=${GOPROXY}
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /watchvuln .

FROM alpine:3.21
COPY --from=backend /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=backend /usr/local/go/lib/time/zoneinfo.zip /usr/share/zoneinfo.zip
ENV ZONEINFO=/usr/share/zoneinfo.zip
RUN addgroup -S watchvuln && adduser -S -G watchvuln watchvuln
WORKDIR /app
COPY --from=backend /watchvuln /app/watchvuln
COPY --from=frontend /src/frontend/dist /app/frontend/dist
RUN mkdir -p /app/data && chown -R watchvuln:watchvuln /app/data
USER watchvuln
ENV TZ=Asia/Shanghai WATCHVULN_ADDR=:18080 WATCHVULN_DATA=/app/data WATCHVULN_ASSETS=/app/frontend/dist
EXPOSE 18080
VOLUME ["/app/data"]
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s CMD wget -q -O /dev/null http://127.0.0.1:18080/api/status || exit 1
ENTRYPOINT ["/app/watchvuln"]
