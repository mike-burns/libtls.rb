require 'libtls/config'
require 'libtls/raw'

module LibTLS
class Client
  def initialize(configure:, &block)
    LibTLS.init

    @config = Config.new(configure)

    if (@raw_client = LibTLS::Raw.tls_client) == nil
      raise "tls_client failed"
    end

    if LibTLS::Raw::tls_configure(@raw_client, @config.as_raw) < 0
      raise "tls_configure: #{LibTLS::Raw.tls_error(@raw_client)}"
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
      if LibTLS::Raw.tls_connect(@raw_client, hostname, port.to_s) < 0
        raise "tls_connect: #{LibTLS::Raw.tls_error(@raw_client)}"
      end

      opened_client = OpenedClient.new(@raw_client)
      block.call(opened_client)
    ensure
      opened_client && opened_client.close
    end
  end

  def finish
    @config.free
    LibTLS::Raw.tls_free(@raw_client)
  end
end

private

class OpenedClient
  READ_LEN = 1024

  def initialize(raw_client)
    @raw_client = raw_client
  end

  def close
    if LibTLS::Raw.tls_close(@raw_client) < 0
      raise "tls_close: #{LibTLS::Raw.tls_error(@raw_client)}"
    end
  end

  def write(str)
    FFI::MemoryPointer.new(:size_t) do |outlen|
      FFI::MemoryPointer.new(:uchar, str.length + 1) do |str_ptr|
        str_ptr.put_string(0, str)

        if LibTLS::Raw.tls_write(@raw_client, str_ptr, str.length, outlen) < 0
          raise "tls_write: #{LibTLS::Raw.tls_error(@raw_client)}"
        end
      end
    end
  end

  def read
    str = ""

    FFI::MemoryPointer.new(:size_t) do |outlen|
      FFI::MemoryPointer.new(:uchar, READ_LEN, true) do |buf|
        loop do
          if LibTLS::Raw.tls_read(@raw_client, buf, READ_LEN, outlen) < 0
            raise "tls_read: #{LibTLS::Raw.tls_error(@raw_client)}"
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
