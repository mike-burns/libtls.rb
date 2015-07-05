require 'ffi'

module LibTLS
##
# Direct access to C functions
#
# This module encapsulates the communication between Ruby and the C libtls
# library.
#
# We recommend that you consider the object-oriented API in {LibTLS::Client}
# and {LibTLS::Server} before reaching for these functions. However, not all
# functions are accessible via those two classes.
#
# The {LibTLS::Server}, {LibTLS::Client}, and {LibTLS::OpenedClient}
# instances provide access to the +FFI::Pointer+ that is used by functions in
# this module, so that you can mostly use the OO interface but directly access
# the C functions when needed.
#
# Using functions from here means that you are familiar with the tls_init(3)
# man page and the +FFI::MemoryPointer+ class.
#
# Much of the documentation in this file is taken from the tls_init(3) man
# page. Such documentation is copyright 2014 Ted Unangst, licensed under the
# ISC license.
module Raw
  extend FFI::Library

  ffi_lib "libtls.so"

  ##
  # The version of the libtls API.
  TLS_API = 20141031

  ##
  # Select the TLS 1.0 protocol
  TLS_PROTOCOL_TLSv1_0 = (1 << 1)
  ##
  # Select the TLS 1.1 protocol
  TLS_PROTOCOL_TLSv1_1 = (1 << 2)
  ##
  # Select the TLS 1.2 protocol
  TLS_PROTOCOL_TLSv1_2 = (1 << 3)
  ##
  # Select any TLS 1.x protocol
  TLS_PROTOCOL_TLSv1 = \
    TLS_PROTOCOL_TLSv1_0 | TLS_PROTOCOL_TLSv1_1 | TLS_PROTOCOL_TLSv1_2

  ##
  # Select any TLS protocol of any version
  TLS_PROTOCOLS_ALL = TLS_PROTOCOL_TLSv1
  ##
  # Select the default, suggested TLS protocol
  #
  # Do not use any protocol except this one unless you understand why you are
  # doing so.
  TLS_PROTOCOLS_DEFAULT = TLS_PROTOCOL_TLSv1_2

  ##
  # A read operation is necessary to continue
  TLS_READ_AGAIN = -2
  ##
  # A write operation is necessary to continue
  TLS_WRITE_AGAIN = -3

  ##
  # @!method tls_init()
  #
  #   Initialize the libtls library
  #
  #   The +tls_init+ function should be called once before any function is used.
  #   It may be called more than once, but not concurrently.
  #
  #   @return [Fixnum] 0 on success, -1 on error
  attach_function :tls_init, [], :int

  ##
  # @!method tls_error(ctx)
  #
  #   Produce the error message on the context
  #
  #   The +tls_error+ function may be used to retrieve a string containing more
  #   information about the most recent error.
  #
  #   @param ctx [FFI::Pointer] the TLS context
  #   @return [String] the error message for the most recent error
  attach_function :tls_error, [:pointer], :string

  ##
  # @!group Create and free configuration objects
  # @!method tls_config_new()
  #
  #   Produce a new +tls_config+ context
  #
  #   Before a connection is created, a configuration must be created. The
  #   +tls_config_new+ function returns a new default configuration that can be
  #   used for future connections. Several functions exist to change the
  #   options of the configuration; see below.
  #
  #   @return [FFI::Pointer] a +tls_config+ context or +FFI::Pointer::NULL+ on
  #     failure. Check using +#null?+.
  attach_function :tls_config_new, [], :pointer
  # @!endgroup

  ##
  # @!group Create and free configuration objects
  # @!method tls_config_free(config)
  #
  #   Free the +tls_config+ object
  #
  #   When no more contexts are to be created, the +tls_config+ object should be
  #   freed by calling +tls_config_free+.
  #
  #   @param config [FFI::Pointer] the TLS config
  #   @return [nil] +void+
  attach_function :tls_config_free, [:pointer], :void
  # @!endgroup

  ##
  # @!method tls_config_parse_protocols(protocols, protostr)
  #
  #   Parse a protocol string into a bitmask
  #
  #   The +tls_config_parse_protocols+ function parses a protocol string and
  #   returns the corresponding value via the +protocols+ argument. This value
  #   can then be passed to the {#tls_config_set_protocols} function. The
  #   protocol string is a comma or colon separated list of keywords. Valid
  #   keywords are +tlsv1.0+, +tlsv1.1+, +tlsv1.2+, +all+ (all supported
  #   protocols), +default+ (an alias for +secure+), +legacy+ (an alias for
  #   +all+) and +secure+ (currently TLSv1.2 only). If a value has a negative
  #   prefix (in the form of a leading exclamation mark) then it is removed
  #   from the list of available protocols, rather than being added to it.
  #
  #   @param protocols [FFI::Pointer] a +uint32_t+ pointer to store the parse
  #     result
  #   @param protostr [String] the protocol string
  #   @return [Fixnum] 0 on success, -1 on error
  #
  #   @todo This is untested. Please {https://github.com/mike-burns/libtls.rb#contributing contribute a patch}.
  attach_function :tls_config_parse_protocols, [:uint32_t, :string], :int

  ##
  # @!group Client configuration
  # @!method tls_config_set_ca_file(config, ca_file)
  #
  #   Use the given file as the certificate authority file
  #
  #   +tls_config_set_ca_file+ sets the filename used to load a file containing
  #   the root certificates.
  #
  #   This applies to clients.
  #
  #   @param config [FFI::Pointer] the TLS config
  #   @param ca_file [String] absolute path to the file containing the root
  #     certificates
  #   @return [Fixnum] 0 on success, -1 on error
  attach_function :tls_config_set_ca_file, [:pointer, :string], :int

  ##
  # @!method tls_config_set_ca_path(config, ca_path)
  #
  #   Use the directory specified to find the root certificate file
  #
  #   +tls_config_set_ca_path+ sets the path (directory) which should be
  #   searched for root certificates.
  #
  #   This applies to clients.
  #
  #   @param config [FFI::Pointer] the TLS config
  #   @param ca_path [String] absolute path to the directory containing the
  #     root certificates
  #   @return [Fixnum] 0 on success, -1 on error
  #
  #   @todo This is untested. Please {https://github.com/mike-burns/libtls.rb#contributing contribute a patch}.
  attach_function :tls_config_set_ca_path, [:pointer, :string], :int

  ##
  # @!method tls_config_set_ca_mem(config, cert, len)
  #
  #   Use the root certicate from memory
  #
  #   +tls_config_set_ca_mem+ sets the root certificates directly from memory.
  #
  #   This applies to clients.
  #
  #   @param config [FFI::Pointer] the TLS config
  #   @param cert [FFI::Pointer] uint8_t pointer to the cert
  #   @param len [Fixnum] number of bytes in the cert
  #   @return [Fixnum] 0 on success, -1 on error
  #
  #   @todo This is untested. Please {https://github.com/mike-burns/libtls.rb#contributing contribute a patch}.
  attach_function :tls_config_set_ca_mem, [:pointer, :pointer, :size_t], :int
  # @!endgroup

  ##
  # @!group Client and server configuration
  # @!method tls_config_set_cert_file(config, cert_file)
  #
  #   Use the given file as the certficate file
  #
  #   +tls_config_set_ca_file+ sets sets file from which the public certificate
  #   will be read.
  #
  #   This applies to clients and servers.
  #
  #   @param config [FFI::Pointer] the TLS config
  #   @param cert_file [String] absolute path to the file containing the public
  #     certificate
  #   @return [Fixnum] 0 on success, -1 on error
  attach_function :tls_config_set_cert_file, [:pointer, :string], :int

  ##
  # @!method tls_config_set_cert_mem(config, cert, len)
  #
  #   Use the given file as the public certificate
  #
  #   +tls_config_set_cert_mem+ sets the public certificate directly from
  #   memory.
  #
  #   This applies to clients and servers.
  #
  #   @param config [FFI::Pointer] the TLS config
  #   @param cert [FFI::Pointer] uint8_t pointer to the cert
  #   @param len [Fixnum] number of bytes in the cert
  #   @return [Fixnum] 0 on success, -1 on error
  #
  #   @todo This is untested. Please {https://github.com/mike-burns/libtls.rb#contributing contribute a patch}.
  attach_function :tls_config_set_cert_mem, [:pointer, :pointer, :size_t], :int
  # @!endgroup

  ##
  # @!group Client and server configuration
  # @!method tls_config_set_ciphers(config, ciphers)
  #
  #   Use the given list of ciphers
  #
  #   +tls_config_set_ciphers+ sets the list of ciphers that may be used.
  #
  #   This applies to clients and servers.
  #
  #   @param config [FFI::Pointer] the TLS config
  #   @param ciphers [String] a list of ciphers to use
  #   @return [Fixnum] 0 on success, -1 on error
  attach_function :tls_config_set_ciphers, [:pointer, :string], :int
  # @!endgroup

  ##
  # @!group Server configuration
  # @!method tls_config_set_dheparams(config, params)
  #
  #   Tune the dheparams
  #
  #   This applies to servers.
  #
  #   @param config [FFI::Pointer] the TLS config
  #   @param params [String] one of "none" (0), "auto" (-1), or "legacy"
  #     (1024). The default is "none".
  #   @return [Fixnum] 0 on success, -1 on error
  #
  #   @todo This is untested. Please {https://github.com/mike-burns/libtls.rb#contributing contribute a patch}.
  attach_function :tls_config_set_dheparams, [:pointer, :string], :int

  ##
  # @!method tls_config_set_ecdhecurve(config, name)
  #
  #   Use the specified EC DHE curve
  #
  #   This applies to servers.
  #
  #   @param config [FFI::Pointer] the TLS config
  #   @param name one of "none" (+NID_undef+), "auto" (-1), or any NID value
  #     understood by OBJ_txt2nid (3).
  #   @return [Fixnum] 0 on success, -1 on error
  #
  #   @todo This is untested. Please {https://github.com/mike-burns/libtls.rb#contributing contribute a patch}.
  attach_function :tls_config_set_ecdhecurve, [:pointer, :string], :int

  ##
  # @!method tls_config_set_key_file(config, key_file)
  #
  #   Set the private key via an absolute file path
  #
  #   +tls_config_set_key_file+ sets the file from which the private key will
  #   be read.
  #
  #   This applies to servers.
  #
  #   @param config [FFI::Pointer] the TLS config
  #   @param key_file [String] absolute path to a private key in a file
  #   @return [Fixnum] 0 on success, -1 on error
  attach_function :tls_config_set_key_file, [:pointer, :string], :int

  ##
  # @!method tls_config_set_key_mem(config, key, len)
  #
  #   Set the private key via a value in memory
  #
  #   +tls_config_set_key_mem+ directly sets the private key from memory.
  #
  #   This applies to servers.
  #
  #   @param config [FFI::Pointer] the TLS config
  #   @param key [FFI::Pointer] a uint8_t pointer to the key
  #   @param len [Fixnum] number of bytes in the key
  #   @return [Fixnum] 0 on success, -1 on error
  #
  #   @todo This is untested. Please {https://github.com/mike-burns/libtls.rb#contributing contribute a patch}.
  attach_function :tls_config_set_key_mem, [:pointer, :pointer, :size_t], :int
  # @!endgroup

  ##
  # @!group Client and server configuration
  # @!method tls_config_set_protocols(config, protocols)
  #
  #   Select which protocols are to be used
  #
  #   +tls_config_set_protocols+ sets which versions of the protocol may be
  #   used. Possible values are the bitwise OR of:
  #
  #   - {TLS_PROTOCOL_TLSv1_0}
  #   - {TLS_PROTOCOL_TLSv1_1}
  #   - {TLS_PROTOCOL_TLSv1_2}
  #
  #   Additionally, the values {TLS_PROTOCOL_TLSv1} (TLSv1.0, TLSv1.1 and
  #   TLSv1.2), {TLS_PROTOCOLS_ALL} (all supported protocols) and
  #   {TLS_PROTOCOLS_DEFAULT} (TLSv1.2 only) may be used.
  #
  #   This applies to clients and servers.
  #
  #   @param config [FFI::Pointer] the TLS config
  #   @param protocols [Fixnum] bitmask of the protocols to select
  #   @return [nil] +void+
  attach_function :tls_config_set_protocols, [:pointer, :uint], :void
  # @!endgroup

  ##
  # @!group Client configuration
  # @!method tls_config_set_verify_depth(config, verify_depth)
  #
  #   Set the maximum depth for the certificate chain
  #
  #   See SSL_CTX_set_verify_depth(3) for details.
  #
  #   This applies to clients.
  #
  #   @param config [FFI::Pointer] the TLS config
  #   @param verify_depth [Fixnum] the maximum depth for certificate chain
  #     verification
  #   @return [nil] +void+
  #
  #   @todo This is untested. Please {https://github.com/mike-burns/libtls.rb#contributing contribute a patch}.
  attach_function :tls_config_set_verify_depth, [:pointer, :int], :void
  # @!endgroup

  ##
  # @!group Server configuration
  # @!method tls_config_clear_keys(config)
  #
  #   Clear secret keys from memory
  #
  #   +tls_config_clear_keys+ clears any secret keys from memory.
  #
  #   This applies to servers.
  #
  #   @param config [FFI::Pointer] the TLS config
  #   @return [nil] +void+
  #
  #   @todo This is untested. Please {https://github.com/mike-burns/libtls.rb#contributing contribute a patch}.
  attach_function :tls_config_clear_keys, [:pointer], :void
  # @!endgroup

  ##
  # @!group Client configuration
  # @!method tls_config_insecure_noverifycert(config)
  #
  #   Insecurely disable certficate verification
  #
  #   +tls_config_insecure_noverifycert+ disables certificate verification. Be
  #   extremely careful when using this option.
  #
  #   This applies to clients.
  #
  #   @param config [FFI::Pointer] the TLS config
  #   @return [nil] +void+
  #
  #   @note This method should not be used, and is therefore untested.
  attach_function :tls_config_insecure_noverifycert, [:pointer], :void

  ##
  # @!method tls_config_insecure_noverifyname(config)
  #
  #   Insecurely disable server name verification
  #
  #   +tls_config_insecure_noverifyname+ disables server name verification. Be
  #   careful when using this option.
  #
  #   This applies to clients.
  #
  #   @param config [FFI::Pointer] the TLS config
  #   @return [nil] +void+
  #
  #   @note This method should not be used, and is therefore untested.
  attach_function :tls_config_insecure_noverifyname, [:pointer], :void

  ##
  # @!method tls_config_verify(config)
  #
  #   Restore default verification
  #
  #   +tls_config_verify+ reenables server name and certificate verification.
  #
  #   This applies to clients.
  #
  #   @param config [FFI::Pointer] the TLS config
  #   @return [nil] +void+
  #
  #   @note While this method is fine, getting to this state is not. This
  #     method is therefore untested.
  attach_function :tls_config_verify, [:pointer], :void
  # @!endgroup

  ##
  # @!group Client and server configuration
  # @!method tls_load_file(file, len, password)
  #
  #   Load a certificate or key
  #
  #   +tls_load_file+ loads a certificate or key from disk into memory to be
  #   loaded with {#tls_config_set_ca_mem}, {#tls_config_set_cert_mem} or
  #   {#tls_config_set_key_mem}. A private key will be decrypted if the
  #   optional +password+ argument is specified.
  #
  #   This applies to clients and servers.
  #
  #   @param file [String] the absolute filename
  #   @param len [FFI::Pointer] pointer to a +size_t+ storing the number of
  #     bytes loaded
  #   @param password [String] either +FFI::Pointer::NULL+ or the password for
  #     the private key
  #   @return [FFI::Pointer] pointer to +uint8_t+, the key
  #
  #   @todo This is untested. Please {https://github.com/mike-burns/libtls.rb#contributing contribute a patch}.
  attach_function :tls_load_file, [:string, :pointer, :string], :pointer
  # @!endgroup

  ##
  # @!group Create, prepare, and free a connection context
  # @!method tls_client()
  #
  #   Create a client context
  #
  #   A tls connection is represented as a context. A new context is created by
  #   either the {#tls_client} or {#tls_server} functions. The context can then
  #   be configured with the function {#tls_configure}. The same +tls_config+
  #   object can be used to configure multiple contexts.
  #
  #   +tls_client+ creates a new tls context for client connections.
  #
  #   @return [FFI::Pointer] a +tls+ context or +FFI::Pointer::NULL+ on
  #     failure. Check using +#null?+.
  attach_function :tls_client, [], :pointer

  ##
  # @!method tls_server()
  #
  #   Create a server context
  #
  #   A tls connection is represented as a context. A new context is created by
  #   either the {#tls_client} or {#tls_server} functions. The context can then
  #   be configured with the function {#tls_configure}. The same +tls_config+
  #   object can be used to configure multiple contexts.
  #
  #   +tls_server+ creates a new tls context for server connections.
  #
  #   @return [FFI::Pointer] a +tls+ context or +FFI::Pointer::NULL+ on
  #     failure. Check using +#null?+.
  attach_function :tls_server, [], :pointer

  ##
  # @!method tls_configure(ctx, config)
  #
  #   Apply the configuration to the context
  #
  #   +tls_configure+ readies a tls context for use by applying the
  #   configuration options.
  #
  #   The same +tls_config+ object can be used to configure multiple contexts.
  #
  #   @param ctx [FFI::Pointer] a TLS context
  #   @param config [FFI::Pointer] the TLS config
  #   @return [Fixnum] 0 on success, -1 on error
  attach_function :tls_configure, [:pointer, :pointer], :int

  ##
  # @!method tls_reset(ctx)
  #
  #   Reset a context to a newly-initialized state
  #
  #   @param ctx [FFI::Pointer] a TLS context
  #   @return [nil] +void+
  #
  #   @todo This is untested. Please {https://github.com/mike-burns/libtls.rb#contributing contribute a patch}.
  attach_function :tls_reset, [:pointer], :void

  ##
  # @!method tls_close(ctx)
  #
  #   Close the TLS connection
  #
  #   After use, a +tls+ context should be closed with +tls_close+, and then
  #   freed by calling {#tls_free}. When no more contexts are to be created, the
  #   +tls_config+ object should be freed by calling {#tls_config_free}.
  #
  #   +tls_close+ closes a connection after use. If the connection was
  #   established using +#tls_connect_fds+, only the TLS layer will be closed
  #   and it is the caller's responsibility to close the file descriptors.
  #
  #   @param ctx [FFI::Pointer] a TLS context
  #   @return [Fixnum] 0 on success, -1 on error, {TLS_READ_AGAIN} if a read
  #     opreation is necessary to continue, {TLS_WRITE_AGAIN} if a write
  #     operation is necessary to continue. In case of a {TLS_READ_AGAIN} or
  #     {TLS_WRITE_AGAIN}, the caller should repeat the call.
  attach_function :tls_close, [:pointer], :int

  ##
  # @!method tls_free(ctx)
  #
  #   Free memory for the TLS context
  #
  #   After use, a +tls+ context should be closed with +tls_close+, and then
  #   freed by calling {#tls_free}. When no more contexts are to be created, the
  #   +tls_config+ object should be freed by calling {#tls_config_free}.
  #
  #   +tls_free+ frees a tls context after use.
  #
  #   @param ctx [FFI::Pointer] a TLS context
  attach_function :tls_free, [:pointer], :void
  # @!endgroup

  ##
  # @!group Initiate a connection and perform I/O
  # @!method tls_connect(ctx, host, port)
  #
  #   Open a TLS connection to the +host+ and +port+
  #
  #   A client connection is initiated after configuration by calling
  #   +tls_connect+. This function will create a new socket, connect to the
  #   specified host and port, and then establish a secure connection.
  #
  #   +tls_connect+ connects a client context to the server named by host. The
  #   port may be numeric or a service name. If it is +FFI::Pointer::NULL+ then
  #   a host of the format "hostname:port" is permitted.
  #
  #   @param ctx [FFI::Pointer] a TLS context
  #   @param host [String] the server to connect to, as an IPv4 address, an
  #     IPv6 address, anything that can be resolved by +getaddrinfo+.
  #   @param port [String] the port as a number, service name, or NULL pointer.
  #     If it is a NULL pointer, the host is parsed for the port number.
  #   @return [Fixnum] 0 on success, -1 on error, {TLS_READ_AGAIN} if a read
  #     opreation is necessary to continue, {TLS_WRITE_AGAIN} if a write
  #     operation is necessary to continue. In case of a {TLS_READ_AGAIN} or
  #     {TLS_WRITE_AGAIN}, the caller should repeat the call.
  attach_function :tls_connect, [:pointer, :string, :string], :int

  ##
  # @!method tls_connect_fds(ctx, fd_read, fd_write, servername)
  #
  #   Upgrade an existing connection to secure
  #
  #   +tls_connect_fds+ connects a client context to a pair of existing file
  #   descriptors.
  #
  #   @param ctx [FFI::Pointer] a TLS context
  #   @param fd_read [Fixnum] the read file descriptor
  #   @param fd_write [Fixnum] the write file descriptor
  #   @param servername [String] the name of the server, as matched in the
  #     certificate
  #   @return [Fixnum] 0 on success, -1 on error, {TLS_READ_AGAIN} if a read
  #     opreation is necessary to continue, {TLS_WRITE_AGAIN} if a write
  #     operation is necessary to continue. In case of a {TLS_READ_AGAIN} or
  #     {TLS_WRITE_AGAIN}, the caller should repeat the call.
  #
  #   @todo This is untested. Please {https://github.com/mike-burns/libtls.rb#contributing contribute a patch}.
  attach_function :tls_connect_fds, [:pointer, :int, :int, :string], :int

  ##
  # @!method tls_connect_servername(ctx, host, port, servername)
  #
  #   Open a TLS connection to the +host+ and +port+, verifying against
  #   +servername+
  #
  #   The +tls_connect_servername+ function has the same behaviour as
  #   {#tls_connect}, however the name to use for verification is explicitly
  #   provided, rather than being inferred from the host value.
  #
  #   @param ctx [FFI::Pointer] a TLS context
  #   @param host [String] the server to connect to, as an IPv4 address, an
  #     IPv6 address, anything that can be resolved by +getaddrinfo+.
  #   @param port [String] the port as a number, service name, or NULL pointer.
  #     If it is a NULL pointer, the host is parsed for the port number.
  #   @param servername [String] the server name to verify the certificate
  #     against
  #   @return [Fixnum] 0 on success, -1 on error, {TLS_READ_AGAIN} if a read
  #     opreation is necessary to continue, {TLS_WRITE_AGAIN} if a write
  #     operation is necessary to continue. In case of a {TLS_READ_AGAIN} or
  #     {TLS_WRITE_AGAIN}, the caller should repeat the call.
  #
  #   @todo This is untested. Please {https://github.com/mike-burns/libtls.rb#contributing contribute a patch}.
  attach_function :tls_connect_servername,
    [:pointer, :string, :string, :string], :int

  ##
  # @!method tls_connect_socket(ctx, s, servername)
  #
  #   Upgrade an existing socket
  #
  #   +tls_connect_socket+ connects a client context to an already established
  #   socket connection.
  #
  #   @param ctx [FFI::Pointer] a TLS context
  #   @param s [Fixnum] the file descriptor for a socket
  #   @param servername [String] the server name to verify the certificate
  #     against
  #   @return [Fixnum] 0 on success, -1 on error, {TLS_READ_AGAIN} if a read
  #     opreation is necessary to continue, {TLS_WRITE_AGAIN} if a write
  #     operation is necessary to continue. In case of a {TLS_READ_AGAIN} or
  #     {TLS_WRITE_AGAIN}, the caller should repeat the call.
  #
  #   @todo This is untested. Please {https://github.com/mike-burns/libtls.rb#contributing contribute a patch}.
  attach_function :tls_connect_socket, [:pointer, :int, :string], :int

  ##
  # @!method tls_accept_fds(ctx, cctx, fd_read, fd_write)
  #
  #   Perform the TLS handshake on an established pair of file descriptors
  #
  #   +tls_accept_fds+ creates a new context suitable for reading and writing
  #   on an existing pair of file descriptors and returns it in +*cctx+. A
  #   configured server context should be passed in +ctx+ and +*cctx+ should be
  #   initialized to NULL.
  #
  #   @see #tls_accept_socket
  #
  #   @param ctx [FFI::Pointer] a TLS context
  #   @param cctx [FFI::Pointer] a reference to a TLS context
  #   @param fd_read [Fixnum] the read file descriptor
  #   @param fd_write [Fixnum] the write file descriptor
  #   @return [Fixnum] 0 on success, -1 on error, {TLS_READ_AGAIN} if a read
  #     opreation is necessary to continue, {TLS_WRITE_AGAIN} if a write
  #     operation is necessary to continue. In case of a {TLS_READ_AGAIN} or
  #     {TLS_WRITE_AGAIN}, the caller should repeat the call.
  #
  #   @todo This is untested. Please {https://github.com/mike-burns/libtls.rb#contributing contribute a patch}.
  attach_function :tls_accept_fds, [:pointer, :pointer, :int, :int], :int

  ##
  # @!method tls_accept_socket(ctx, cctx, socket)
  #
  #   Perform the TLS handshake on an established socket
  #
  #   A server can accept a new client connection by calling
  #   +tls_accept_socket+ on an already established socket connection.
  #
  #   +tls_accept_socket+ creates a new context suitable for reading and
  #   writing on an already established socket connection and returns it in
  #   +*cctx+. A configured server context should be passed in +ctx+ and
  #   +*cctx+ should be initialized to +NULL+.
  #
  #   The pattern looks like this:
  #
  #     cctx_ptr = FFI::MemoryPointer.new(:pointer)
  #     LibTLS::Raw.tls_accept_socket(ctx, cctx_ptr, client_sock.fileno)
  #     cctx = cctx_ptr.read_pointer
  #
  #   @param ctx [FFI::Pointer] a TLS context
  #   @param cctx [FFI::Pointer] a reference to a TLS context
  #   @param socket [Int] the file descriptor of an established socket that is
  #     connected to a client. Use +Socket#fileno+ to get the file descriptor
  #     of a Socket instance.
  #   @return [Fixnum] 0 on success, -1 on error, {TLS_READ_AGAIN} if a read
  #     opreation is necessary to continue, {TLS_WRITE_AGAIN} if a write
  #     operation is necessary to continue. In case of a {TLS_READ_AGAIN} or
  #     {TLS_WRITE_AGAIN}, the caller should repeat the call.
  attach_function :tls_accept_socket, [:pointer, :pointer, :int], :int

  ##
  # @!method tls_read(ctx, buf, buflen, outlen)
  #
  #   Read from the socket
  #
  #   +tls_read+ reads +buflen+ bytes of data from the socket into +buf+. The
  #   amount of data read is returned in +outlen+.
  #
  #   The pattern is as follows:
  #
  #
  #     READ_LEN = 1024
  #     FFI::MemoryPointer.new(:size_t) do |outlen|
  #       FFI::MemoryPointer.new(:uchar, READ_LEN, true) do |buf|
  #         loop do
  #           if LibTLS::Raw.tls_read(ctx, buf, READ_LEN, outlen) < 0
  #             raise LibTLS::CError, "tls_read: #{LibTLS::Raw.tls_error(ctx)}"
  #           end
  #
  #           do_something_with( buf.get_string(0, outlen.get_int(0)) )
  #
  #           if READ_LEN > outlen.get_int(0)
  #             break
  #           end
  #         end
  #       end
  #     end
  #
  #   @param ctx [FFI::Pointer] a TLS context
  #   @param buf [FFI::Pointer] allocated memory for a +buflen+ number of
  #     +uchars+
  #   @param buflen [Fixnum] the number of bytes to read
  #   @param outlen [FFI::Pointer] the number of bytes read
  #   @return [Fixnum] 0 on success, -1 on error, {TLS_READ_AGAIN} if a read
  #     opreation is necessary to continue, {TLS_WRITE_AGAIN} if a write
  #     operation is necessary to continue. In the case of a {TLS_READ_AGAIN} the
  #     caller should repeat the call. In the case of a {TLS_WRITE_AGAIN}, the
  #     caller should call {#tls_write}.
  attach_function :tls_read, [:pointer, :pointer, :size_t, :pointer], :int

  ##
  # @!method tls_write(ctx, buf, buflen, outlen)
  #
  #   Write data to the socket
  #
  #   +tls_write+ writes +buflen+ bytes of data from +buf+ to the socket. The
  #   amount of data written is returned in +outlen+.
  #
  #   The pattern is as follows:
  #
  #     STR = "HELLO\r\n"
  #
  #     FFI::MemoryPointer.new(:size_t) do |outlen|
  #       FFI::MemoryPointer.new(:uchar, STR.length + 1) do |str_ptr|
  #         str_ptr.put_string(0, STR)
  #
  #         if LibTLS::Raw.tls_write(ctx, str_ptr, STR.length, outlen) < 0
  #           raise LibTLS::CError, "tls_write: #{LibTLS::Raw.tls_error(ctx)}"
  #         end
  #       end
  #     end
  #
  #   @param ctx [FFI::Pointer] a TLS context
  #   @param buf [FFI::Pointer] a pointer to the string of +uchar+s
  #   @param buflen [Fixnum] the number of bytes to write
  #   @param outlen [FFI::Pointer] the number of bytes written
  #   @return [Fixnum] 0 on success, -1 on error, {TLS_READ_AGAIN} if a read
  #     opreation is necessary to continue, {TLS_WRITE_AGAIN} if a write
  #     operation is necessary to continue. In the case of a {TLS_READ_AGAIN} the
  #     caller should call {#tls_read}. In the case of a {TLS_WRITE_AGAIN}, the
  #     caller should repeat the call.
  attach_function :tls_write, [:pointer, :pointer, :size_t, :pointer], :int
  # @!endgroup
end
end
