# Server deployment

The server runs three containers: Web, API, and PostgreSQL. Redis is not used by the current API and is intentionally omitted.

1. Upload the complete release directory to the server. The application source code is not required.
2. Set a public HTTPS `WEB_ORIGIN` and terminate TLS in an existing reverse proxy that forwards to `127.0.0.1:3000`.
3. Generate distinct random `JWT_SECRET` and `OTP_SECRET` values of at least 32 characters.
4. Load the supplied images and start the stack:

```sh
gzip -dc forge-images-amd64-0.1.1.tar.gz | docker load
docker compose --env-file .env.production -f docker-compose.production.yml up -d --no-build
```

The database migration is applied automatically only when the PostgreSQL volume is first created. Apply later migrations explicitly before upgrading an existing deployment.

Do not commit `.env.production`, database backups, API keys, or TLS private keys. End-user Windows/macOS clients do not install PostgreSQL and never receive the server database password.
