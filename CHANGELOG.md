# Changelog

## 0.1.0

First Ruby SDK for sending a document, reading envelope status, downloading a completed file, and verifying webhook signatures.

Install from GitHub with `gem "signingflow", github: "Signingflow/signingflow-ruby"` until the gem is on RubyGems.

The API host is HTTPS `api.signingflow.com` unless `allow_custom_base_url` is set. A file path is read only from `upload_root`. A hard link is rejected, and the file is not opened when the runtime cannot refuse a symlink. `construct_event` returns `payload` and `body_sha256` of the raw body. A 409 is an idempotency error only when the body says the key was already used. A timed-out send is returned only when `sent_time` falls in the two minutes after the call started. The client sends `Accept-Encoding: identity` and stops reading an API response at 8 MB.
