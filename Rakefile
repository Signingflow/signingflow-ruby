# frozen_string_literal: true

task :test do
  abort unless system(Gem.ruby, "-Ilib", "-Itest", "test/run.rb")
end

task default: :test
