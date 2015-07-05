require 'libtls/config'
require 'libtls/raw'

module LibTLS
class Client
  attr_reader :ctx

  def initialize(configure:, &block)
    if LibTLS::Raw.tls_init < 0
      raise LibTLS::UnknownCError, "tls_init"
    end

    @config = Config.new(configure)

    if (@ctx = LibTLS::Raw.tls_client) == nil
      raise LibTLS::UnknownCError, "tls_client"
    end

    if LibTLS::Raw::tls_configure(ctx, @config.as_raw) < 0
      raise LibTLS::CError, "tls_configure: #{LibTLS::Raw.tls_error(ctx)}"
    end

    if block
      begin
        block.call(self)
      ensure
        self.finish
      end
    end
  end

  def connect(hostname, port, &block)
    opened_client = nil

    begin
      if LibTLS::Raw.tls_connect(ctx, hostname, port.to_s) < 0
        raise LibTLS::CError, "tls_connect: #{LibTLS::Raw.tls_error(ctx)}"
      end

      opened_client = OpenedClient.new(ctx)
      block.call(opened_client)
    ensure
      opened_client && opened_client.close
    end
  end

  def finish
    @config.free
    LibTLS::Raw.tls_free(ctx)
  end
end

private

class OpenedClient
  READ_LEN = 1024

  attr_reader :ctx

  def initialize(ctx)
    @ctx = ctx
  end

  def close
    if LibTLS::Raw.tls_close(ctx) < 0
      raise LibTLS::CError, "tls_close: #{LibTLS::Raw.tls_error(ctx)}"
    end
  end

  def write(str)
    FFI::MemoryPointer.new(:size_t) do |outlen|
      FFI::MemoryPointer.new(:uchar, str.length + 1) do |str_ptr|
        str_ptr.put_string(0, str)

        if LibTLS::Raw.tls_write(ctx, str_ptr, str.length, outlen) < 0
          raise LibTLS::CError, "tls_write: #{LibTLS::Raw.tls_error(ctx)}"
        end
      end
    end
  end

  def read
    str = ""

    FFI::MemoryPointer.new(:size_t) do |outlen|
      FFI::MemoryPointer.new(:uchar, READ_LEN, true) do |buf|
        loop do
          if LibTLS::Raw.tls_read(ctx, buf, READ_LEN, outlen) < 0
            raise LibTLS::CError, "tls_read: #{LibTLS::Raw.tls_error(ctx)}"
          end

          str += buf.get_string(0, outlen.get_int(0))

          if READ_LEN > outlen.get_int(0)
            break
          end
        end
      end
    end

    str
  end
end
end
