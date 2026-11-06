# frozen_string_literal: true

require_relative "lib/signingflow/version"

Gem::Specification.new do |spec|
  spec.name = "signingflow"
  spec.version = Signingflow::VERSION
  spec.authors = ["Signingflow"]
  spec.summary = "Official Ruby SDK for the Signingflow API."
  spec.description = "Send a document, read envelope status, and verify webhook signatures with the Signingflow API."
  spec.homepage = "https://github.com/Signingflow/signingflow-ruby"
  spec.license = "MIT"
  spec.required_ruby_version = ">= 3.2"
  spec.files = Dir["lib/**/*.rb", "resources/allowlist.json", "README.md", "CHANGELOG.md", "LICENSE"]
  spec.require_paths = ["lib"]
  spec.metadata = {
    "homepage_uri" => spec.homepage,
    "source_code_uri" => spec.homepage,
    "changelog_uri" => "#{spec.homepage}/blob/main/CHANGELOG.md",
    "rubygems_mfa_required" => "true"
  }

  spec.add_development_dependency "minitest", "~> 5.25"
  spec.add_development_dependency "rake", "~> 13.2"
  spec.add_development_dependency "simplecov", "~> 0.22"
  spec.add_development_dependency "webmock", "~> 3.24"
end
