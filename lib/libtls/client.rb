require 'libtls/config'
require 'libtls/raw'

module LibTLS
##
# This class represents a TLS client connecting to a server. Here is a sample
# HTTPS session; this #get method will produce the content at the specified
# path on the hostname:
#
#   def get(hostname, path)
#     content = nil
#     config = { ca_file: '/etc/ssl/cert.pem' }
#   
#     LibTLS::Client.new(configure: config) do |client|
#       content = client.connect("mike-burns.com", 443) do |c|
#         c.write(http_get(hostname, path))
#         c.read
#       end
#     end
#   
#     content
#   end
#   
#   def http_get(hostname, path)
#     ["GET #{path} HTTP/1.1",
#      "User-Agent: libtls.rb/0.1",
#      "Host: #{hostname}"].join("\r\n") +
#      "\r\n"
#   end
class Client
  ##
  # The FFI wrapper around the struct tls object
  #
  # This is only useful for calling any of the {LibTLS::Raw} methods.
  attr_reader :ctx

  ##
  # Construct a new [Client] instance
  #
  # Once constructed, it runs the block. When the block finishes, it calls
  # {#finish}.
  #
  # @param configure [Hash] a mapping from setting name to value. The setting
  #   name is any of {LibTLS::Config::VALID_SET_CONFIGS}; the value is either a
  #   scalar value passed through to the C function, or an array of values. For
  #   example:
  #     { ca_file: 'ca.pem', key_mem: [key_ptr, 48] }
  # @yieldparam [Client] self an initialized and configured instance of self
  # @raise [LibTLS::UnknownCError] if +tls_init+ or +tls_client+ fails
  # @raise [LibTLS::CError] if +tls_configure+ fails
  def initialize(configure:, &block)
    if LibTLS::Raw.tls_init < 0
      raise LibTLS::UnknownCError, "tls_init"
    end

    @config = Config.new(configure)

    if (@ctx = LibTLS::Raw.tls_client).null?
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

  ##
  # Open a connection with the server
  #
  # This method negotiates the TLS connection with the +hostname+, at the
  # +port+. Once connected, it passes the connected client to the block. Once
  # the block finishes, it calls {OpenedClient#close} on the connection.
  #
  # @param hostname [String] the server to connect to, as an IPv4 address, an
  #   IPv6 address, or anything that can be resolved by +getaddrinfo+.
  # @param port [#to_s] the port on the server to connect to
  # @yieldparam [OpenedClient] client a connected client
  # @raise [LibTLS::CError] if the +tls_connect+ fails
  # @return the result of the block
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

  ##
  # Release any memory held on to by the C library
  #
  # This method must be called either implicitly by passing a block to
  # {#initialize}, or explicitly by you.
  def finish
    @config.free
    LibTLS::Raw.tls_free(ctx)
  end
end

private

##
# A TLS client connected to a server
#
# This class must be instantiated only by {LibTLS::Client#connect} and
# {LibTLS::Server#accept}.
#
# When finished, {#close} must be called. This is implicitly handled for you by
# passing a block to the methods mentioned above.
class OpenedClient
  READ_LEN = 1024
  private_constant :READ_LEN

  ##
  # The FFI wrapper around the struct tls object
  #
  # This is only useful for calling any of the {LibTLS::Raw} methods.
  attr_reader :ctx

  ##
  # @api private
  def initialize(ctx)
    @ctx = ctx
  end

  ##
  # Close this connection
  #
  # This method must be called either implicitly by passing a block to
  # {LibTLS::Client#connect} or {LibTLS::Server#accept}, or explicitly by you.
  def close
    if LibTLS::Raw.tls_close(ctx) < 0
      raise LibTLS::CError, "tls_close: #{LibTLS::Raw.tls_error(ctx)}"
    end
  end

  ##
  # Write the string to the connection
  #
  # @param [String] str the string to write
  # @raise [LibTLS::CError] if +tls_write+ fails
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

  ##
  # Read a string from the connection
  #
  # @raise [LibTLS::CError] if +tls_read+ fails
  # @return [String] the accumulated buffer
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
