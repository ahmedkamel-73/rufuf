# Rufuf 1.0 — Production Gate

## Required before public launch
1. Create the production D1 database and apply all migrations.
2. Create a PRIVATE production R2 bucket.
3. Set `SESSION_SECRET` as a Cloudflare secret.
4. Configure the first admin through a secure one-time setup; never commit credentials.
5. Configure the production HTTPS/custom domain.
6. Test registration/login and all three roles.
7. Test publisher submission and admin approval/rejection.
8. Test PDF/cover upload, size/type validation and private R2 access.
9. Test the reader on Android Chrome.
10. Test platform-ad and publisher-ad isolation.
11. Test search, category filtering, reading counters and reading progress.
12. Verify no direct public R2 URL exposes a book.
13. Run a security review and rate-limit/authentication checks.
14. Test a full backup/export and recovery procedure for D1.
15. Deploy a tested Worker version, then promote it to production.

## Revenue model
No book sales and no payment gateways.
Platform ads belong to Rufuf; publisher ads belong to the publisher.
