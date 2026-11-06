# signingflow

[![CI](https://github.com/Signingflow/signingflow-ruby/actions/workflows/ci.yml/badge.svg)](https://github.com/Signingflow/signingflow-ruby/actions/workflows/ci.yml)
[![Coverage](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/Signingflow/signingflow-ruby/badges/coverage.json)](https://github.com/Signingflow/signingflow-ruby/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-MIT-blue)](LICENSE)

Ruby SDK for the Signingflow calls used to send a document, read envelope status, and receive webhooks.

The gem talks to `https://api.signingflow.com`. Keep the API key on your server. Ruby 3.2 or newer is required.

```ruby
gem "signingflow", github: "Signingflow/signingflow-ruby"
```

The gem name is `signingflow`. Install it from [GitHub](https://github.com/Signingflow/signingflow-ruby) until it is published on RubyGems.

```ruby
require "signingflow"

client = Signingflow::Client.new(
  ENV.fetch("SIGNINGFLOW_API_KEY"),
  workspace_id: ENV.fetch("SIGNINGFLOW_WORKSPACE_ID"),
  env: "sandbox",
)

envelope = client.envelopes.send_document(
  title: "NDA",
  file: pdf_bytes,
  filename: "contract.pdf",
  recipients: [{ name: "Ada Lovelace", email: "ada@example.com" }],
  message: "Please sign",
)
```

`file` is the raw bytes. A disk path is `path:`, and it is read only from `upload_root`. That directory must be one this process writes. The open refuses a symlink, a hard link, and a path that leaves the directory. If this Ruby cannot open a path without following a symlink, the read is refused.

The client sends `Accept-Encoding: identity` and stops reading once an API response passes 8 MB.

`env` is `sandbox` or `live`. The client always sends `X-Request-Env`. A missing environment header is treated as live by the API.

`base_url` must be `https`. The host is `api.signingflow.com` unless `allow_custom_base_url` is set. A username or password on the URL is rejected.

## Send and read

`envelopes.prepare_draft` stores one PDF and creates a draft. It does not email anyone.

`envelopes.send_document` stores the PDF, creates the draft, adds the recipients to the first document, and sends. `envelopes.send_from_template` starts from `templates/{id}`.

If update or send fails, the error includes `envelope_name` for the draft that was saved. After a timeout, the client returns the envelope only when `sent_time` is within two minutes after the call started and not more than a minute ahead of this clock. An older or far-future timestamp is an error.

`envelopes.list(directory: "needAction")` reads pages of 10. `page_size` can be from 1 to 1000.

`envelopes.download_completed(name)` reads the envelope first. It requests the download URL only when the state is `COMPLETED`. The download call returns `uri`, `download_time`, and `etag`. This client does not GET `uri`. Treat that URL as untrusted until your application checks the host. Do not send the API key to it.

`envelopes.remind(name)` notifies people who can still sign. The call is not idempotent.

## Idempotency

Creates and sends send a UUID `idempotencyKey` in the JSON body. The same key is stored for the whole environment. A repeat returns HTTP 409 and does not return the original resource. The SDK raises `Signingflow::IdempotencyError` with `resource_name` when the error includes one. It does not treat that response as success.

Pass the same `idempotency_key` only to retry one request after a timeout. `update` and `remind` are not retried automatically.

## Webhooks

```ruby
destination = client.webhook_urls.create(
  display_name: "Envelope events",
  http_request_uri: "https://example.com/webhooks/signingflow",
  events: ["DOC_ENVELOPE_COMPLETED"],
)

secret = Signingflow.signing_secret_of(destination)
```

Store that secret from the create response. A later `retrieve` does not include it. Do not set `http_config`. `auth: "NONE"` is rejected.

```ruby
event = Signingflow.construct_event(raw_body, signature_header, secret, previous_secret: previous, previous_signature: previous_signature)
event.payload
event.body_sha256
```

The signature is lowercase hex HMAC-SHA256 of the raw body. There is no timestamp. Compare `X-Signingflow-Signature` or `X-Webhook-Signature`. During a grace window, also pass the previous header and secret. Parse JSON only after the MAC matches. `body_sha256` is the SHA-256 of those raw bytes. Store it and reject a delivery you have already seen.

## Errors

| Class | When |
| --- | --- |
| `Signingflow::AuthenticationError` | HTTP 401 |
| `Signingflow::PermissionError` | HTTP 403 |
| `Signingflow::IdempotencyError` | HTTP 409 whose body mentions idempotency |
| `Signingflow::RateLimitError` | HTTP 429 |
| `Signingflow::InvalidRequestError` | Other HTTP 4xx |
| `Signingflow::APIError` | HTTP 5xx, or a response larger than 8 MB |
| `Signingflow::ConnectionError` | The API could not be reached or timed out |
| `Signingflow::SignatureVerificationError` | The webhook MAC does not match |
