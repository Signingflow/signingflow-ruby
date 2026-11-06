# frozen_string_literal: true

require "pathname"

module Signingflow
  module Jail
    module_function

    def read(root, requested, max_bytes)
      base = File.realpath(root)
      resolved = File.expand_path(requested.to_s, base)
      parent_real = File.realpath(File.dirname(resolved))
      raise Error, "outside root" if escapes?(base, parent_real)

      leaf = File.basename(resolved)
      raise Error, "outside root" if leaf.empty? || leaf == "." || leaf == ".."

      path = File.join(parent_real, leaf)
      raise Error, "outside root" if escapes?(base, path) || File.expand_path(path) == File.expand_path(base)
      raise Error, "nofollow" unless Jail.nofollow_available?

      io = IO.new(IO.sysopen(path, File::RDONLY | File::NOFOLLOW))
      begin
        info = io.stat
        raise Error, "not a file" unless info.file?
        raise Error, "hard link" if info.nlink > 1
        raise Error, "too large" if info.size > max_bytes

        io.read(info.size) || +""
      ensure
        io.close
      end
    end

    def self.nofollow_available?
      defined?(File::NOFOLLOW) == "constant"
    end

    def escapes?(base, target)
      relative = Pathname(target).relative_path_from(Pathname(base)).to_s
      return true if relative.empty?

      relative.split(/[\\\/]/).include?("..")
    end
  end
end
