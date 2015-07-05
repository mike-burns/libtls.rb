require 'libtls/raw'
require 'libtls/exn'

module LibTLS
  ##
  # A TLS configuration
  #
  # This object is an abstraction over the libtls configuration. It can be used
  # as a shorthand for configuring the struct tls context.
  #
  #   config = LibTLS::Config.new(
  #     ca_path: '/etc/ssl',
  #     key_mem: [key_ptr, 512]
  #   )
  #   LibTLS::Raw.tls_configure(ctx, config.as_raw)
  #   config.free
class Config
  ##
  # Keys that can be configured
  #
  # This is derived from the +tls_config_set_*+ functions in {LibTLS::Raw}.
  VALID_SET_CONFIGS = %i(
    ca_file ca_path ca_mem cert_file cert_mem ciphers dheparams ecdhecurve
    key_file key_mem protocols verify_depth
  )

  ##
  # Return a new instance of Config
  #
  # @param [Hash] config_hash the Ruby representation of the configuration. The
  #   keys are any of {VALID_SET_CONFIGS}; the value is either a scalar value,
  #   or an array. The array is splatted into the appropriate C function.
  #
  # @option config_hash [String] ca_file The filename used to load a file containing
  #   the root certificates. (_Client_)
  # @option config_hash [String] ca_path The path (directory) which should be
  #   searched for root certificates. (_Client_)
  # @option config_hash [[FFI::Pointer, Fixnum]] ca_mem Set the root certificates
  #   directly from memory. (_Client_)
  # @option config_hash [String] cert_file Set file from which the public
  #   certificate will be read. (_Client_ _and_ _server_)
  # @option config_hash [[FFI::Pointer, Fixnum]] cert_mem Set the public
  #   certificate directly from memory. (_Client_ _and_ _server_)
  # @option config_hash [String] ciphers Set the list of ciphers that may be
  #   used. (_Client_ _and_ _server_)
  # @option config_hash [String] dheparams Set the dheparams option to either
  #   "none" (0), "auto" (-1), or "legacy" (1024). The default is "none".
  #   (_Server_)
  # @option config_hash [String] ecdhecurve Set the ecdhecurve option to one of
  #   "none" (+NID_undef+), "auto" (-1), or any NID value understood by
  #   OBJ_txt2nid (3).  (_Server_)
  # @option config_hash [String] keyfile Set the file from which the private
  #   key will be read. (_Server_)
  # @option config_hash [[FFI::Pointer, Fixnum]] key_mem Directly set the
  #   private key from memory. (_Server_)
  # @option config_hash [Fixnum] protocols Sets which versions of the protocol
  #   may be used, as documented in {LibTLS::Raw#tls_config_set_protocols}.
  #   (_Client_ _and_ _server_)
  # @option config_hash [Fixnum] verify_depth Set the verify depth as
  #   documented under SSL_CTX_set_verify_depth(3). (_Client_)
  def initialize(config_hash)
    @config_hash = config_hash
  end

  ##
  # Convert this object into the C representation
  #
  # This builds a struct tls_config pointer, sets the values on it as dictated
  # by the hash passed in, and returns the struct tls_config pointer.
  #
  # The return value must be freed using {#free}.
  #
  # @return [FFI::Pointer] the completed struct tls_config pointer
  # @raise [LibTLS::UnknownCError] if +tls_config_new+ or the appropriate
  #   +tls_config_set_*+ fails
  def as_raw
    @raw_config ||= buld_raw_config
  end

  ##
  # Release any memory held on to by the C library
  #
  # This method must be called when finished.
  def free
    LibTLS::Raw.tls_config_free(as_raw)
  end

  private

  def buld_raw_config
    if (raw = LibTLS::Raw.tls_config_new).null?
      raise LibTLS::UnknownCError, "tls_config_new"
    end

    valid_config_hash.each do |key, value|
      ret = LibTLS::Raw.send("tls_config_set_#{key}", raw, *value)

      if ret && ret < 0
        raise LibTLS::UnknownCError, "tls_config_set_#{key}"
      end
    end

    raw
  end

  def valid_config_hash
    @config_hash.select do |key, value|
      VALID_SET_CONFIGS.include?(key)
    end
  end
end
end
