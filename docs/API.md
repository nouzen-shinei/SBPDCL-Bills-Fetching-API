# API Documentation

This repository includes a small Vercel-hosted Python API that performs the encryption required by the SBPDCL portal flow used in `appsscript.js`.

The API is intentionally narrow: it only encrypts request payloads and returns the encrypted values to Google Apps Script.

## Base URL

The base URL depends on your own Vercel deployment.

Example:

`https://your-vercel-project.vercel.app`

If you are using the sample script in this repository, the example URL currently shown there is:

`https://sbpdcl-bills-fetching-api.vercel.app/api/crypto`

That is the author’s own deployed endpoint. Anyone publishing or using this repository should replace it with their own Vercel URL.

## Endpoint

### `POST /api/crypto`

Encrypts payloads for SBPDCL request flow.

This endpoint accepts a JSON body with a required `type` field.

## Request Types

The endpoint supports two modes.

### 1. Static encryption

Use this mode for payloads that do not require an RSA public key.

Request body:

```json
{
	"type": "static",
	"data": {
		"action": "getAllWebConfigurations"
	}
}
```

Behavior:

- The server serializes `data` into compact JSON.
- It derives an AES key and IV from the fixed password used by the SBPDCL flow.
- It encrypts the payload with AES-CBC.
- It returns a base64 string with the encrypted result.

Response:

```json
{
	"result": "U2FsdGVkX1..."
}
```

### 2. Dynamic encryption

Use this mode when the payload must be encrypted with a per-request AES key and that AES key must then be encrypted with the RSA public key returned by SBPDCL.

Request body:

```json
{
	"type": "dynamic",
	"data": {
		"action": "getNscToken"
	},
	"rsa_key": "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A..."
}
```

Behavior:

- The server serializes `data` into compact JSON.
- It generates a random 32-byte AES key and a random 16-byte IV.
- It encrypts the JSON payload with AES-CBC.
- It encrypts the AES key using the supplied RSA public key.
- It returns the encrypted key, encrypted payload, and IV.

Response:

```json
{
	"encryptedKey": "...",
	"payload": "...",
	"iv": "..."
}
```

## Error Responses

The API returns standard JSON error responses.

### Invalid type

```json
{
	"error": "Invalid crypto type"
}
```

HTTP status: `400`

### Internal failure

```json
{
	"error": "<error message>"
}
```

HTTP status: `500`

## How the Google Apps Script Uses the API

The Apps Script calls this endpoint through `getCrypto()` in [appsscript.js](../appsscript.js).

The flow is:

1. Use `type: "static"` to encrypt the first configuration request.
2. Read the RSA key from SBPDCL’s configuration response.
3. Use `type: "dynamic"` with the RSA key for token and billing requests.
4. Pass the returned encrypted output to SBPDCL’s backend endpoints.

In short, the Vercel service is a helper encryption layer between Google Apps Script and the SBPDCL portal.

## Local Development Notes

The API code lives in [api/index.py](../api/index.py).

Dependencies are listed in [requirements.txt](../requirements.txt):

- Flask
- pycryptodome
- requests

Typical local steps:

1. Install the Python dependencies.
2. Run the function locally with Vercel or your preferred Flask-compatible test setup.
3. Send a POST request to `/api/crypto` and confirm the JSON output.

## Example Usage with curl

Static request:

```bash
curl -X POST "https://your-vercel-project.vercel.app/api/crypto" \
	-H "Content-Type: application/json" \
	-d '{"type":"static","data":{"action":"getAllWebConfigurations"}}'
```

Dynamic request:

```bash
curl -X POST "https://your-vercel-project.vercel.app/api/crypto" \
	-H "Content-Type: application/json" \
	-d '{"type":"dynamic","data":{"action":"getNscToken"},"rsa_key":"YOUR_RSA_KEY_HERE"}'
```

## Notes for Public Repositories

- Do not hard-code your own Vercel deployment URL in public examples unless you clearly label it as a sample.
- Users must deploy their own API and update `VERCEL_CRYPTO_URL` in their Google Apps Script.
- If SBPDCL changes its encryption flow, update this API and the Apps Script together.
