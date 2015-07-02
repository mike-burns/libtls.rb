require 'libtls/config'
require 'libtls/raw'

module LibTLS
class Server
  def initialize(configure:, &block)
    LibTLS.init

    @config = Config.new(configure)

    if (@raw_server = LibTLS::Raw.tls_server) == nil
      raise "tls_server failed"
    end

    if LibTLS::Raw::tls_configure(@raw_server, @config.as_raw) < 0
      raise "tls_configure: #{LibTLS::Raw.tls_error(@raw_server)}"
    end

    if block
      begin
        block.call(self)
      ensure
        self.finish
      end
    end
  end

  def accept(client_socket, &block)
    cctx_ptr = FFI::MemoryPointer.new(:pointer)

    if tls_accept(cctx_ptr, client_socket) == -1
      raise "tls_accept_socket: #{LibTLS::Raw.tls_error(@raw_server)}"
    end

    cctx = cctx_ptr.read_pointer

    opened_client = OpenedClient.new(cctx)
    block.call(opened_client)
  ensure
    opened_client && opened_client.close
  end

  def finish
    @config.free
    LibTLS::Raw.tls_free(@raw_server)
  end

  private

  def tls_accept(cctx_ptr, client_sock)
    ret = LibTLS::Raw.tls_accept_socket(
      @raw_server, cctx_ptr, client_sock.fileno)

    if [LibTLS::READ_AGAIN, LibTLS::WRITE_AGAIN].include?(ret)
      tls_accept(cctx_ptr, client_sock)
    else
      ret
    end
  end
end
end
