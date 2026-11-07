# frozen_string_literal: true

require "test_helper"
require "tmpdir"
require "fileutils"

class SdkTest < Minitest::Test
  API_KEY = "df_sk_testsecret"
  ID = "11111111-1111-4111-8111-111111111111"
  ENVELOPE = "envelopes/#{ID}"
  STORAGE_ID = "22222222-2222-4222-8222-222222222222"
  STORAGE = "storages/#{STORAGE_ID}"
  TEMPLATE = "templates/33333333-3333-4333-8333-333333333333"
  DESTINATION = "webhookUrls/44444444-4444-4444-8444-444444444444"
  DELIVERY = "webhooks/55555555-5555-4555-8555-555555555555"

  def test_constructor_rejects_missing_configuration
    assert_raises(Signingflow::Error) { Signingflow::Client.new("", workspace_id: "ws", env: "sandbox") }
    assert_raises(Signingflow::Error) { Signingflow::Client.new(API_KEY, workspace_id: " ", env: "sandbox") }
    assert_raises(Signingflow::Error) { Signingflow::Client.new(API_KEY, workspace_id: "ws", env: "prod") }
    assert_raises(Signingflow::Error) { Signingflow::Client.new(API_KEY, workspace_id: "ws", env: "sandbox", base_url: "http://api.signingflow.com") }
    assert_raises(Signingflow::Error) { Signingflow::Client.new(API_KEY, workspace_id: "ws", env: "sandbox", base_url: "https://user:pass@api.signingflow.com") }
    assert_raises(Signingflow::Error) { Signingflow::Client.new(API_KEY, workspace_id: "ws", env: "sandbox", base_url: "https://example.com") }
    assert_raises(Signingflow::Error) { Signingflow::Client.new(API_KEY, workspace_id: "ws", env: "sandbox", base_url: "not a url") }
    assert_raises(Signingflow::Error) { Signingflow::Client.new(API_KEY, workspace_id: "ws", env: "sandbox", timeout: 0) }
    assert_raises(Signingflow::Error) { Signingflow::Client.new(API_KEY, workspace_id: "ws", env: "sandbox", max_network_retries: -1) }
    assert_raises(Signingflow::Error) { Signingflow::Client.new(API_KEY, workspace_id: "ws", env: "sandbox", upload_hosts: ["com"]) }
    Signingflow::Client.new(API_KEY, workspace_id: "ws", env: "SANDBOX", base_url: "https://example.com/", allow_custom_base_url: true)
  end

  def test_requests_send_auth_headers_and_camel_case_query
    stub_request(:get, %r{/v1/envelopes/#{ID}:view}).to_return(json(200, { "name" => ENVELOPE, "displayName" => "NDA" }))
    envelope = client(env: "live", channel: "ads", funnel: "spring").envelopes.retrieve(ENVELOPE, read_mask: "documents")
    assert_equal "NDA", envelope.display_name
    assert_requested :get, "https://api.signingflow.com/v1/envelopes/#{ID}:view?readMask=documents",
                     headers: {
                       "Authorization" => "Bearer #{API_KEY}",
                       "X-Request-Workspace-Id" => "ws",
                       "X-Request-Env" => "LIVE",
                       "X-Request-Channel" => "ads",
                       "X-Request-Funnel" => "spring",
                       "X-Request-Source" => "signingflow-ruby/0.1.0",
                       "Accept-Encoding" => "identity"
                     }
    request = Net::HTTP::Get.new(URI("https://api.signingflow.com/v1/envelopes/#{ID}:view"), { "Accept-Encoding" => "identity" })
    refute request.decode_content
  end

  def test_maps_status_errors_and_redacts_secrets
    body = {
      "code" => 3,
      "message" => "bad Bearer #{API_KEY} and df_sk_live",
      "metadata" => { "trace_code" => "trace-1" },
      "details" => [{ "fieldViolations" => [{ "field" => "token", "description" => "see ?X-Goog-Signature=abc" }] }]
    }
    stub_request(:post, %r{addEnvelope}).to_return(json(400, body, "x-request-id" => "req-1"))
    error = assert_raises(Signingflow::InvalidRequestError) do
      client.envelopes.create(display_name: "NDA", storage_id: STORAGE_ID)
    end
    assert_equal 400, error.status_code
    assert_equal 3, error.grpc_code
    assert_equal "trace-1", error.trace_code
    assert_equal "req-1", error.request_id
    assert_equal "envelope:write", error.capability
    assert_includes error.message, "df_sk_redacted"
    assert_includes error.message, "Bearer [redacted]"
    refute_includes error.message, API_KEY
    assert_includes error.field_violations.first["description"], "[redacted]"

    quiet = client(max_network_retries: 0)
    stub_request(:get, %r{:view}).to_return(json(401, { "message" => "nope" }))
    assert_raises(Signingflow::AuthenticationError) { quiet.envelopes.retrieve(ENVELOPE) }
    stub_request(:get, %r{:view}).to_return(json(403, { "message" => "nope" }))
    assert_raises(Signingflow::PermissionError) { quiet.envelopes.retrieve(ENVELOPE) }
    stub_request(:get, %r{:view}).to_return(json(429, "slow down", "rate-limit-reset-after" => "2000-01-01T00:00:00Z"))
    raised = assert_raises(Signingflow::RateLimitError) { quiet.envelopes.retrieve(ENVELOPE) }
    assert_equal "2000-01-01T00:00:00Z", raised.retry_after
    stub_request(:patch, %r{/v1/envelopes/#{ID}\z}).to_return(json(500, { "message" => "down" }))
    assert_raises(Signingflow::APIError) { client.envelopes.update(ENVELOPE, { "display_name" => "NDA" }) }
    assert_requested :patch, %r{/v1/envelopes/#{ID}\z}, times: 1
    stub_request(:post, %r{:addEnvelope}).to_return(json(409, { "message" => "idempotency key used", "metadata" => { "resource_url" => ENVELOPE } }))
    replay = assert_raises(Signingflow::IdempotencyError) { client.envelopes.create(display_name: "NDA", storage_id: STORAGE_ID) }
    assert_equal ENVELOPE, replay.resource_name
    stub_request(:post, %r{:addEnvelope}).to_return(json(409, { "message" => "conflict" }))
    assert_raises(Signingflow::InvalidRequestError) { client.envelopes.create(display_name: "NDA", storage_id: STORAGE_ID) }
    stub_request(:get, %r{:view}).to_return(status: 200, body: "{", headers: { "Content-Type" => "application/json" })
    assert_raises(Signingflow::APIError) { client.envelopes.retrieve(ENVELOPE) }
    stub_request(:get, %r{:view}).to_return(status: 200, body: "pdf", headers: { "Content-Type" => "application/pdf" })
    assert_raises(Signingflow::APIError) { client.envelopes.retrieve(ENVELOPE) }
    stub_request(:get, %r{:download}).to_return(status: 200, body: "", headers: { "Content-Type" => "application/json" })
    assert_equal "", client.envelopes.download(ENVELOPE).uri
  end

  def test_retries_idempotent_writes_and_reads_not_update_or_remind
    stub_request(:post, %r{:send}).to_return(
      json(500, { "message" => "later" }, "rate-limit-retry-after" => "1999-01-01T00:00:00Z"),
      json(200, { "name" => ENVELOPE })
    )
    assert_equal ENVELOPE, client.envelopes.send(ENVELOPE).name
    assert_requested :post, %r{:send}, times: 2

    stub_request(:post, %r{:remind}).to_return(json(500, { "message" => "no" }))
    assert_raises(Signingflow::APIError) { client.envelopes.remind(ENVELOPE) }
    assert_requested :post, %r{:remind}, times: 1

    stub_request(:get, %r{/v1/envelopes\?}).to_return(
      json(500, { "message" => "later" }),
      json(200, { "envelopes" => [{ "name" => ENVELOPE }], "nextPageToken" => "next" })
    )
    page = client.envelopes.list(directory: "needAction")
    assert_equal "next", page.next_page_token
    assert_equal ENVELOPE, page.data.first.name
  end

  def test_connection_failures_expose_the_idempotency_key
    stub_request(:post, %r{:send}).to_raise(Errno::ECONNREFUSED)
    error = assert_raises(Signingflow::ConnectionError) { client(max_network_retries: 0).envelopes.send(ENVELOPE) }
    assert_match(/\A[0-9a-f-]{36}\z/i, error.idempotency_key)
    assert_equal 0, error.status_code

    stub_request(:post, %r{:send}).to_timeout
    timed = assert_raises(Signingflow::ConnectionError) { client(max_network_retries: 0).envelopes.send(ENVELOPE) }
    assert_equal 408, timed.status_code
    assert_equal "The API timed out.", timed.message
  end

  def test_rejects_a_non_uuid_idempotency_key_and_a_key_in_the_query
    assert_raises(Signingflow::InvalidRequestError) do
      client.envelopes.create(display_name: "NDA", storage_id: STORAGE_ID, idempotency_key: "same-key")
    end
    assert_raises(Signingflow::InvalidRequestError) { client.envelopes.retrieve(ENVELOPE, read_mask: API_KEY) }
    encoded_key = "df_sk_a/b c+"
    encoded = Signingflow::Client.new(encoded_key, workspace_id: "ws", env: "sandbox", max_network_retries: 0)
    assert_raises(Signingflow::InvalidRequestError) { encoded.envelopes.retrieve(ENVELOPE, read_mask: encoded_key) }
    assert_raises(Signingflow::InvalidRequestError) { encoded.envelopes.list(directory: "needAction", page_token: encoded_key) }
    assert_raises(Signingflow::InvalidRequestError) { encoded.envelopes.list(directory: "needAction", read_mask: "prefix #{encoded_key}") }
    refute Signingflow::Path.query_contains_secret("readMask=documents", encoded_key)
    assert Signingflow::Path.query_contains_secret("readMask=df_sk_a%2Fb+c%2B", encoded_key)
    assert Signingflow::Path.query_contains_secret("readMask=%zz", encoded_key)
    assert_raises(Signingflow::InvalidRequestError) { client.envelopes.retrieve("envelopes/not-an-id") }
    assert_raises(Signingflow::InvalidRequestError) { client.envelopes.list(directory: " ") }
    assert_raises(Signingflow::InvalidRequestError) { client.envelopes.list(directory: "needAction", page_size: 0) }
    assert_raises(Signingflow::InvalidRequestError) { client.envelopes.create(display_name: " ", storage_id: STORAGE_ID) }
    assert_raises(Signingflow::InvalidRequestError) { client.envelopes.create(display_name: "NDA", storage_id: " ") }
    assert_raises(Signingflow::InvalidRequestError) { Signingflow::Path.fill("/v1/{name}", {}) }
    assert_raises(Signingflow::InvalidRequestError) { Signingflow::Path.fill("/v1/{name}", { "name" => "envelopes/has space" }) }
  end

  def test_stores_a_file_with_put_then_acknowledge
    signed = "https://storage.googleapis.com/bucket/file?X-Goog-Signature=abc"
    stub_storage(signed)
    stub_request(:put, signed).to_return(status: 200, body: "")
    stub_request(:post, %r{batchAcknowledgeUpload}).to_return(json(200, {}))
    stored = client.files.create(file: "%PDF", filename: "contract.pdf")
    assert_equal STORAGE, stored.name
    assert_equal STORAGE_ID, stored.id
    assert_requested :put, signed, headers: { "Content-Type" => "application/pdf", "x-goog-if-generation-match" => "0" } do |request|
      refute request.headers.key?("Authorization")
    end
    assert_requested :post, %r{batchAcknowledgeUpload}
  end

  def test_upload_failures_stop_before_acknowledge
    stub_storage("http://storage.googleapis.com/file")
    assert_raises(Signingflow::InvalidRequestError) { client.files.create(file: "%PDF", filename: "a.pdf") }
    assert_not_requested :post, %r{batchAcknowledgeUpload}

    stub_storage("https://evil.example/file")
    assert_raises(Signingflow::InvalidRequestError) { client.files.create(file: "%PDF", filename: "a.pdf") }

    stub_storage("https://storage.googleapis.com/file")
    stub_request(:put, %r{storage.googleapis.com}).to_return(status: 500, body: "")
    assert_raises(Signingflow::APIError) { client(max_network_retries: 0).files.create(file: "%PDF", filename: "a.pdf") }

    stub_request(:put, %r{storage.googleapis.com}).to_raise(Errno::ECONNREFUSED)
    assert_raises(Signingflow::ConnectionError) { client(max_network_retries: 0).files.create(file: "%PDF", filename: "a.pdf") }

    stub_request(:post, %r{batchAddStorage}).to_return(json(200, { "storages" => [] }))
    assert_raises(Signingflow::APIError) { client.files.create(file: "%PDF", filename: "a.pdf") }
    assert_raises(Signingflow::InvalidRequestError) { client.files.create(file: "%PDF") }
    assert_raises(Signingflow::InvalidRequestError) { client.files.create }
    assert_raises(Signingflow::InvalidRequestError) { client.files.create(file: "%PDF", path: "a.pdf", filename: "a.pdf") }
  end

  def test_put_412_still_acknowledges_and_a_custom_host_is_allowed
    signed = "https://uploads.example.com/bucket/file"
    stub_storage(signed)
    stub_request(:put, signed).to_return(status: 412, body: "")
    stub_request(:post, %r{batchAcknowledgeUpload}).to_return(json(200, {}))
    stored = client(upload_hosts: ["uploads.example.com"]).files.create(file: "hello", filename: "note.txt", mime_type: "text/plain")
    assert_equal STORAGE_ID, stored.id
    assert_requested :post, %r{batchAcknowledgeUpload}
  end

  def test_send_document_follows_the_skill_order
    stub_upload_flow
    stub_request(:post, %r{addEnvelope}).to_return(json(200, { "envelope" => { "uid" => ID } }))
    stub_request(:get, %r{:view}).to_return(json(200, view_body))
    stub_request(:patch, %r{/v1/envelopes/#{ID}\z}).to_return(json(200, { "name" => ENVELOPE }))
    stub_request(:post, %r{:send}).to_return(json(200, { "name" => ENVELOPE, "sent_time" => Time.now.utc.iso8601 }))
    envelope = client.envelopes.send_document(
      title: "NDA",
      file: "%PDF",
      filename: "contract.pdf",
      recipients: [{ name: "Ada Lovelace", email: "ada@example.com" }],
      message: "Please sign"
    )
    assert_equal ENVELOPE, envelope.name
    assert_requested :patch, %r{/v1/envelopes/#{ID}\z} do |request|
      body = JSON.parse(request.body)
      assert_equal "SIGNER", body.dig("documents", 0, "participants", 0, "role")
      assert_equal "ada@example.com", body.dig("documents", 0, "participants", 0, "alternate_email")
    end
  end

  def test_prepare_draft_stops_before_send_and_download_waits_for_completed
    stub_upload_flow
    stub_request(:post, %r{addEnvelope}).to_return(json(200, { "name" => ENVELOPE }))
    draft = client.envelopes.prepare_draft(title: "NDA", file: "%PDF", filename: "contract.pdf", message: "hold")
    assert_equal ENVELOPE, draft.name
    assert_not_requested :post, %r{:send}

    stub_request(:get, %r{:view}).to_return(json(200, { "progress" => { "state" => "SENT" } }))
    error = assert_raises(Signingflow::InvalidRequestError) { client.envelopes.download_completed(ENVELOPE) }
    assert_equal ENVELOPE, error.envelope_name

    stub_request(:get, %r{:view}).to_return(json(200, { "progressStatus" => "COMPLETED" }))
    stub_request(:get, %r{:download}).to_return(json(200, { "uri" => "https://files.example/a", "downloadTime" => "t", "etag" => "e" }))
    downloaded = client.envelopes.download_completed(ENVELOPE)
    assert_equal "https://files.example/a", downloaded.uri
    assert_equal "t", downloaded.download_time
    assert_equal "e", downloaded.etag
  end

  def test_send_from_template_and_timed_out_send_views_the_envelope
    stub_request(:post, %r{/v1/templates/.+:use}).to_return(json(200, { "envelope" => { "name" => ENVELOPE } }))
    stub_request(:get, %r{:view}).to_return(json(200, view_body.merge("sentTime" => (Time.now + 1).utc.iso8601)))
    stub_request(:patch, %r{/v1/envelopes/#{ID}\z}).to_return(json(200, {}))
    stub_request(:post, %r{:send}).to_timeout
    envelope = client(max_network_retries: 0).envelopes.send_from_template(
      template: TEMPLATE,
      recipients: [{ "name" => "Ada", "email" => "ada@example.com" }]
    )
    assert_equal ENVELOPE, envelope.name
    assert_requested :post, %r{:send}, times: 1
    assert_requested :get, %r{:view}, times: 2
  end

  def test_send_recovery_does_not_treat_an_older_or_future_envelope_as_this_call
    stub_request(:post, %r{/v1/templates/.+:use}).to_return(json(200, { "name" => ENVELOPE }))
    stub_request(:get, %r{:view}).to_return(json(200, view_body.merge("sent_time" => "2000-01-01T00:00:00Z")))
    stub_request(:patch, %r{/v1/envelopes/#{ID}\z}).to_return(json(200, {}))
    stub_request(:post, %r{:send}).to_timeout
    error = assert_raises(Signingflow::ConnectionError) do
      client(max_network_retries: 0).envelopes.send_from_template(template: TEMPLATE, recipients: [{ name: "Ada", email: "ada@example.com" }])
    end
    assert_equal ENVELOPE, error.envelope_name

    stub_request(:get, %r{:view}).to_return(json(200, view_body.merge("sent_time" => "2099-01-01T00:00:00Z")))
    future = assert_raises(Signingflow::ConnectionError) do
      client(max_network_retries: 0).envelopes.send_from_template(template: TEMPLATE, recipients: [{ name: "Ada", email: "ada@example.com" }])
    end
    assert_equal ENVELOPE, future.envelope_name
  end

  def test_idempotency_replay_returns_the_viewed_envelope
    stub_request(:post, %r{/v1/templates/.+:use}).to_return(json(200, { "name" => ENVELOPE }))
    stub_request(:get, %r{:view}).to_return(json(200, view_body.merge("sent_time" => "2099-01-01T00:00:00Z")))
    stub_request(:patch, %r{/v1/envelopes/#{ID}\z}).to_return(json(200, {}))
    stub_request(:post, %r{:send}).to_return(json(409, { "message" => "idempotency", "metadata" => { "resource_url" => ENVELOPE } }))
    envelope = client.envelopes.send_from_template(template: TEMPLATE, recipients: [{ name: "Ada", email: "ada@example.com" }])
    assert_equal ENVELOPE, envelope.name

    stub_request(:post, %r{:send}).to_return(json(409, { "message" => "idempotency", "metadata" => { "resource_id" => ID } }))
    mismatch = assert_raises(Signingflow::IdempotencyError) do
      client.envelopes.send_from_template(template: TEMPLATE, recipients: [{ name: "Ada", email: "ada@example.com" }])
    end
    assert_equal ENVELOPE, mismatch.envelope_name
  end

  def test_a_filesystem_path_stays_inside_upload_root
    Dir.mktmpdir do |dir|
      root = File.join(dir, "root")
      outside = File.join(dir, "outside")
      Dir.mkdir(root)
      Dir.mkdir(outside)
      secret = File.join(outside, "secret.pdf")
      File.binwrite(secret, "%PDF-secret")
      File.binwrite(File.join(root, "contract.pdf"), "%PDF-ok")
      signed = "https://storage.googleapis.com/bucket/file"
      stub_storage(signed)
      stub_request(:put, signed).to_return(status: 200, body: "")
      stub_request(:post, %r{batchAcknowledgeUpload}).to_return(json(200, {}))
      stored = client(upload_root: root).files.create(path: "contract.pdf")
      assert_equal STORAGE, stored.name

      error = assert_raises(Signingflow::InvalidRequestError) { client(upload_root: root).files.create(path: "../outside/secret.pdf") }
      assert_match(/outside upload_root/, error.message)
      link = File.join(root, "linked.pdf")
      File.link(secret, link)
      linked = assert_raises(Signingflow::InvalidRequestError) { client(upload_root: root).files.create(path: "linked.pdf") }
      assert_match(/hard link/, linked.message)
      File.symlink(secret, File.join(root, "alias.pdf"))
      alias_error = assert_raises(Signingflow::InvalidRequestError) { client(upload_root: root).files.create(path: "alias.pdf") }
      assert_match(/could not be read/, alias_error.message)
      Signingflow::Jail.define_singleton_method(:nofollow_available?) { false }
      begin
        missing = assert_raises(Signingflow::InvalidRequestError) { client(upload_root: root).files.create(path: "contract.pdf") }
        assert_match(/could not be read/, missing.message)
      ensure
        Signingflow::Jail.define_singleton_method(:nofollow_available?) { defined?(File::NOFOLLOW) == "constant" }
      end
    end
    assert_raises(Signingflow::InvalidRequestError) { client.files.create(path: "contract.pdf") }
    assert_raises(Signingflow::InvalidRequestError) { client.files.create(file: "x" * (25 * 1024 * 1024 + 1), filename: "big.pdf") }
  end

  def test_rejects_an_api_body_larger_than_8_mb
    stub_request(:get, %r{:view}).to_return(status: 200, body: "{}", headers: { "Content-Type" => "application/json", "Content-Length" => (8 * 1024 * 1024 + 1).to_s })
    error = assert_raises(Signingflow::APIError) { client.envelopes.retrieve(ENVELOPE) }
    assert_match(/8 MB/, error.message)
    full = "x" * (8 * 1024 * 1024)
    assert_raises(Signingflow::APIError) do
      Signingflow::Requestor.consume(status: 200, chunks: [full, "y"])
    end
    assert_equal "ok", Signingflow::Requestor.assemble(status: 200, content_length: 2, chunks: ["ok"])
    streamed = assert_raises(Signingflow::APIError) do
      Signingflow::Requestor.consume(status: 200, chunks: Enumerator.new { |y|
        y << "x"
        y << ("y" * (8 * 1024 * 1024))
      })
    end
    assert_match(/8 MB/, streamed.message)
  end

  def test_lists_page_through_next_tokens
    stub_request(:get, %r{/v1/envelopes\?}).to_return(
      json(200, { "envelopes" => [{ "name" => ENVELOPE }], "nextPageToken" => "one" }),
      json(200, { "envelopes" => [{ "name" => ENVELOPE }], "next_page_token" => "one" })
    )
    page = client.envelopes.list(directory: "waitingOthers", page_size: 10, read_mask: "name")
    assert_equal [ENVELOPE, ENVELOPE], page.auto_paging_to_array.map(&:name)

    stub_request(:get, %r{/v1/webhooks\?}).to_return(json(200, { "webhooks" => [{ "name" => DELIVERY, "event" => "DOC_ENVELOPE_COMPLETED" }] }))
    deliveries = client.webhook_deliveries.list
    assert_equal "DOC_ENVELOPE_COMPLETED", deliveries.data.first.event
    assert_equal [DELIVERY], deliveries.auto_paging_to_array(limit: 1).map(&:name)
  end

  def test_auto_paging_stops_on_a_limit_and_too_many_pages
    calls = 0
    stub_request(:get, %r{/v1/envelopes\?}).to_return do
      calls += 1
      json(200, { "envelopes" => [{ "name" => ENVELOPE }], "nextPageToken" => "page-#{calls}" })
    end
    assert_equal 1, client.envelopes.list(directory: "needAction").auto_paging_to_array(limit: 1).length
    error = assert_raises(Signingflow::InvalidRequestError) do
      client.envelopes.list(directory: "needAction").auto_paging_each { |_item| }
    end
    assert_match(/Too many pages/, error.message)
  end

  def test_webhook_destination_and_deliveries
    stub_request(:post, %r{webhookUrls:add}).to_return(json(200, { "name" => DESTINATION, "signingSecret" => "secret-once" }))
    created = client.webhook_urls.create(
      display_name: "Envelope events",
      http_request_uri: "https://example.com/hooks",
      events: ["DOC_ENVELOPE_COMPLETED"]
    )
    assert_equal "secret-once", Signingflow.signing_secret_of(created)
    stub_request(:get, %r{webhookUrls/.+:view}).to_return(json(200, { "name" => DESTINATION, "signing_secret" => "hidden", "signingSecret" => "hidden" }))
    viewed = client.webhook_urls.retrieve(DESTINATION)
    assert_nil viewed.signing_secret
    refute viewed.to_h.key?("signingSecret")
    stub_request(:post, %r{:test}).to_return(json(500, { "message" => "no" }))
    assert_raises(Signingflow::APIError) { client.webhook_urls.test(DESTINATION) }
    assert_requested :post, %r{:test}, times: 1
    stub_request(:get, %r{/v1/#{DELIVERY}:view}).to_return(json(200, { "name" => DELIVERY }))
    assert_equal DELIVERY, client.webhook_deliveries.retrieve(DELIVERY).name
    assert_raises(Signingflow::InvalidRequestError) { client.webhook_urls.retrieve("nope") }
    assert_raises(Signingflow::InvalidRequestError) { client.webhook_deliveries.retrieve("nope") }
    assert_raises(Signingflow::InvalidRequestError) do
      client.webhook_urls.create(display_name: "", http_request_uri: "https://example.com", events: ["DOC_ENVELOPE_COMPLETED"])
    end
    assert_raises(Signingflow::InvalidRequestError) do
      client.webhook_urls.create(display_name: "ok", http_request_uri: "http://example.com", events: ["DOC_ENVELOPE_COMPLETED"])
    end
    assert_raises(Signingflow::InvalidRequestError) do
      client.webhook_urls.create(display_name: "ok", http_request_uri: "https://example.com", events: [])
    end
    assert_raises(Signingflow::InvalidRequestError) do
      client.webhook_urls.create(display_name: "ok", http_request_uri: "https://example.com", events: ["DOC_ENVELOPE_COMPLETED"], http_config: { auth: "NONE" })
    end
    assert_raises(Signingflow::InvalidRequestError) do
      client.webhook_urls.create(display_name: "ok", http_request_uri: "https://example.com", events: ["DOC_ENVELOPE_COMPLETED"], http_config: { auth: "HMAC" })
    end
  end

  def test_construct_event_checks_the_raw_body_and_the_previous_secret
    raw = '{"event":"DOC_ENVELOPE_COMPLETED"}'
    secret = "current-secret"
    signature = OpenSSL::HMAC.hexdigest("SHA256", secret, raw)
    event = Signingflow.construct_event(raw, signature, secret)
    assert_equal "DOC_ENVELOPE_COMPLETED", event.payload["event"]
    assert_equal OpenSSL::Digest::SHA256.hexdigest(raw), event.body_sha256
    assert_raises(Signingflow::SignatureVerificationError) { Signingflow::Webhook.construct_event(raw, "nope", secret) }
    assert_raises(Signingflow::SignatureVerificationError) { Signingflow.construct_event(raw, signature, "") }
    assert_raises(Signingflow::SignatureVerificationError) { Signingflow.construct_event({ "event" => "x" }, signature, secret) }
    assert_raises(Signingflow::InvalidRequestError) { Signingflow.construct_event("not-json", OpenSSL::HMAC.hexdigest("SHA256", secret, "not-json"), secret) }

    previous = "previous-secret"
    previous_signature = OpenSSL::HMAC.hexdigest("SHA256", previous, raw)
    recovered = Signingflow.construct_event(raw, "wrong", secret, previous_secret: previous, previous_signature: previous_signature)
    assert_equal event.body_sha256, recovered.body_sha256
    assert_raises(Signingflow::SignatureVerificationError) do
      Signingflow.construct_event(raw, "wrong", secret, previous_secret: previous)
    end
  end

  def test_path_retry_and_sleep_helpers
    assert_equal 0, Signingflow::Path.retry_delay_ms(nil, nil)
    now = (Time.now.to_r * 1000).round
    assert_equal 60_000, Signingflow::Path.retry_delay_ms((Time.at((now + 120_000) / 1000.0).utc).iso8601, nil, now)
    assert_equal 0, Signingflow::Path.retry_delay_ms("not-a-time", "2000-01-01T00:00:00Z", now)
    assert_raises(Signingflow::InvalidRequestError) { Signingflow::Path.resolve("https://api.signingflow.com", "https://evil.example/v1") }
    Signingflow::Requestor.sleep_ms(0)
    Signingflow::Requestor.sleep_ms(1)
    assert_equal "", Signingflow.signing_secret_of(nil)
  end

  def test_send_document_reports_a_missing_name_and_missing_document
    stub_upload_flow
    stub_request(:post, %r{addEnvelope}).to_return(json(200, {}))
    assert_raises(Signingflow::APIError) do
      client.envelopes.send_document(title: "NDA", file: "%PDF", filename: "a.pdf", recipients: [{ name: "Ada", email: "ada@example.com" }])
    end
    stub_request(:post, %r{addEnvelope}).to_return(json(200, { "name" => ENVELOPE }))
    stub_request(:get, %r{:view}).to_return(json(200, { "name" => ENVELOPE, "documents" => [] }))
    missing = assert_raises(Signingflow::InvalidRequestError) do
      client.envelopes.send_document(title: "NDA", file: "%PDF", filename: "a.pdf", recipients: [{ name: "Ada", email: "ada@example.com" }])
    end
    assert_equal ENVELOPE, missing.envelope_name
    assert_raises(Signingflow::InvalidRequestError) { client.envelopes.send_document(title: " ", file: "%PDF", filename: "a.pdf", recipients: []) }
    assert_raises(Signingflow::InvalidRequestError) do
      client.envelopes.send_document(title: "NDA", file: "%PDF", filename: "a.pdf", recipients: [{ name: "", email: "ada@example.com" }])
    end
    assert_raises(Signingflow::InvalidRequestError) { client.templates.use("templates/nope") }
    assert_raises(Signingflow::InvalidRequestError) { client.envelopes.prepare_draft(title: " ", file: "%PDF", filename: "a.pdf") }
  end

  private

  def client(**options)
    Signingflow::Client.new(API_KEY, workspace_id: "ws", env: "sandbox", **options)
  end

  def json(status, body, extra_headers = {})
    {
      status: status,
      headers: { "Content-Type" => "application/json" }.merge(extra_headers),
      body: body.is_a?(String) ? body : JSON.generate(body)
    }
  end

  def stub_storage(url)
    stub_request(:post, %r{batchAddStorage}).to_return(json(200, { "storages" => [{ "name" => STORAGE, "preSignedUrl" => url }] }))
  end

  def stub_upload_flow
    signed = "https://storage.googleapis.com/bucket/file"
    stub_storage(signed)
    stub_request(:put, signed).to_return(status: 200, body: "")
    stub_request(:post, %r{batchAcknowledgeUpload}).to_return(json(200, {}))
  end

  def view_body
    {
      "name" => ENVELOPE,
      "display_name" => "NDA",
      "description" => "Please sign",
      "documents" => [{ "uid" => "doc-1", "displayName" => "NDA" }],
      "compliance" => { "profile" => "STANDARD" }
    }
  end
end
