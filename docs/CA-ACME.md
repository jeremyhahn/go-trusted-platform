# Automated Certificate Management Environment

This document provides information regarding the ACME server.


## ACME Server Rate Limiting

The ACME server enforces rate limits on various endpoints to ensure fair usage and prevent abuse. Below are the default rate limiting values for each endpoint.

### Rate Limiting Values

| Endpoint                    | Limit                                        | Key Used for Rate Limiting  |
|-----------------------------|----------------------------------------------|-----------------------------|
| `/new-account`               | 5 requests per hour per IP                   | IP address                  |
| `/new-nonce`                 | 60 requests per minute per IP                | IP address                  |
| `/new-order`                 | 50 requests per week per account (JWS KID)   | JWS Key ID                  |
| `/orders/{id}`               | 5 requests per minute per account (JWS KID)  | JWS Key ID                  |
| `/authz/{id}`                | 5 requests per minute per account (JWS KID)  | JWS Key ID                  |
| `/challenge/{id}`            | 5 requests per minute per account (JWS KID)  | JWS Key ID                  |
| `/cert/{id}`                 | 10 requests per hour per account (JWS KID)   | JWS Key ID                  |
| `/revoke-cert`               | 5 requests per hour per account (JWS KID)    | JWS Key ID                  |
| `/directory`                 | 100 requests per hour per IP                 | IP address                  |

### Explanation

- **Public Endpoints**: Endpoints like `/new-account`, `/new-nonce`, and `/directory` are accessible without authentication and are rate-limited based on the client's IP address.
  
- **JWS-Protected Endpoints**: Endpoints that require JWS authentication (e.g., `/new-order`, `/orders/{id}`, `/cert/{id}`) are rate-limited based on the JWS Key ID (`kid`), which ties the rate limit to the account rather than the client's IP address.

### Notes

- These limits are configurable based on the needs of your infrastructure, but it is recommended to follow the values listed above for a balance between availability and security.
- Rate limiting responses will include a `429 Too Many Requests` status code along with a `Retry-After` header to indicate when the client can retry the request.
