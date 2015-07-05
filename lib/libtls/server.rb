require 'libtls/config'
require 'libtls/raw'

module LibTLS
class Server
  attr :ctx

  def initialize(configure:, &block)
    LibTLS.init

    @config = Config.new(configure)

    if (@ctx = LibTLS::Raw.tls_server) == nil
      raise "tls_server failed"
    end

    if LibTLS::Raw::tls_configure(ctx, @config.as_raw) < 0
      raise "tls_configure: #{LibTLS::Raw.tls_error(ctx)}"
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
      raise "tls_accept_socket: #{LibTLS::Raw.tls_error(ctx)}"
    end

    cctx = cctx_ptr.read_pointer

    opened_client = OpenedClient.new(cctx)
    block.call(opened_client)
  ensure
    opened_client && opened_client.close
  end

  def finish
    @config.free
    LibTLS::Raw.tls_free(ctx)
  end

  private

  def tls_accept(cctx_ptr, client_sock)
    ret = LibTLS::Raw.tls_accept_socket(
      ctx, cctx_ptr, client_sock.fileno)

    if [LibTLS::Raw::TLS_READ_AGAIN, LibTLS::Raw::TLS_WRITE_AGAIN].include?(ret)
      tls_accept(cctx_ptr, client_sock)
    else
      ret
    end
  end
end
end
