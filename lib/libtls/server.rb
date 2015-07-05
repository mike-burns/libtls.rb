require 'libtls/config'
require 'libtls/raw'
require 'libtls/exn'

module LibTLS
##
# Represent a server that communicates over TLS
#
# This class handles the details on using an existing instance of Socket to
# communicate with clients. It knows how to configure the TLS settings and
# negotiate the TLS handshake.
#
# Here is an example method that echos a response over an encrypted channel.
# Note that the issues around creating and maintaining a socket are dealt
# with elsewhere.
#
#   def echo_server(socket)
#     config = {
#         key_file: "thekey.key",
#         cert_file: "thecert.crt"
#     }
#   
#     LibTLS::Server.new(configure: config) do |server|
#       client_socket, _ = socket.accept
#   
#       server.accept(client_socket) do |client|
#         str = client.read
#         client.write(str)
#       end
#     end
#   end
class Server
  ##
  # The FFI wrapper around the struct tls object
  #
  # This is only useful for calling any of the {LibTLS::Raw} methods.
  attr :ctx

  ##
  # Instantiate and configure a TLS server
  #
  # Once constructed, a {Server} instance must be freed with the {#finish}
  # method. If you pass a block to the constructor it will handle this for you.
  #
  # @param configure [Hash] a mapping from setting name to value. The setting
  #   name is any of {LibTLS::Config::VALID_SET_CONFIGS}; the value is either a
  #   scalar value passed through to the C function, or an array of values. For
  #   example:
  #     { ca_file: 'ca.pem', key_mem: [key_ptr, 48] }
  # @yieldparam [Server] self an initialized and configured instance of self
  # @raise [LibTLS::UnknownCError] if +tls_init+ or +tls_server+ fail
  # @raise [LibTLS::CError] if +tls_configure+ fails
  def initialize(configure:, &block)
    if LibTLS::Raw.tls_init < 0
      raise LibTLS::UnknownCError, "tls_init"
    end

    @config = Config.new(configure)

    if (@ctx = LibTLS::Raw.tls_server) == nil
      raise LibTLS::UnknownCError, "tls_server"
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

  ##
  # Negotiate a TLS handshake on an existing socket
  #
  # The client socket is assumed to already have an active connection; for
  # example, +IO.select+ or +Socket#accept+ has been called.
  #
  # The block is run on a connection opened for the client. Once the block
  # finishes, the connection is closed automatically.
  #
  # @param client_socket [Socket] a connected socket
  # @yieldparam [OpenedClient] client the connected client
  # @raise [LibTLS::CError] if +tls_accept_socket+ fails
  # @return the result of the block
  def accept(client_socket, &block)
    cctx_ptr = FFI::MemoryPointer.new(:pointer)

    if tls_accept(cctx_ptr, client_socket) == -1
      raise LibTLS::CError, "tls_accept_socket: #{LibTLS::Raw.tls_error(ctx)}"
    end

    cctx = cctx_ptr.read_pointer

    opened_client = OpenedClient.new(cctx)
    block.call(opened_client)
  ensure
    opened_client && opened_client.close
  end

  ##
  # Release any memory held on to by the C library
  #
  # This method must be called either implicitly by passing a block to
  # {#initialize}, or explicitly by you.
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
