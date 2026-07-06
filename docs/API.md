# API Documentation

## Endpoint

`GET /api/get-sbpdcl-bill`

Downloads the SBPDCL bill PDF for a given CA number.

### Query parameters

- `ca` - required. SBPDCL CA number used to look up the bill.

### Success response

- Status: `200 OK`
- Content type: `application/pdf`
- Body: raw PDF bytes
- Filename: `SBPDCL_<ca>.pdf`

### Error responses

- `400 Bad Request` when `ca` is missing
- `500 Internal Server Error` when the upstream service cannot be reached or returns an unexpected payload

## Flow

1. Fetch SBPDCL configuration to obtain the RSA public key.
2. Build a payload containing the CA number.
3. Encrypt the payload with AES-CBC.
4. Wrap the AES key with RSA.
5. Call the upstream download service.
6. Return the PDF bytes to the client.

## Operational considerations

- Add request timeouts before production use.
- Expect upstream responses to change and handle schema drift defensively.
- If you deploy this publicly, consider rate limiting and logging controls.