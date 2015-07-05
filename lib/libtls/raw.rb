require 'ffi'

module LibTLS
module Raw
  extend FFI::Library

  ffi_lib "libtls.so"

  TLS_API = 20141031

  TLS_PROTOCOL_TLSv1_0 = (1 << 1)
  TLS_PROTOCOL_TLSv1_1 = (1 << 2)
  TLS_PROTOCOL_TLSv1_2 = (1 << 3)
  TLS_PROTOCOL_TLSv1 = \
    TLS_PROTOCOL_TLSv1_0 | TLS_PROTOCOL_TLSv1_1 | TLS_PROTOCOL_TLSv1_2

  TLS_PROTOCOLS_ALL = TLS_PROTOCOL_TLSv1
  TLS_PROTOCOLS_DEFAULT = TLS_PROTOCOL_TLSv1_2

  TLS_READ_AGAIN = -2
  TLS_WRITE_AGAIN = -3

  attach_function :tls_init, [], :int
  attach_function :tls_error, [:pointer], :string
  attach_function :tls_config_new, [], :pointer
  attach_function :tls_config_free, [:pointer], :void
  # TODO: tls_config_parse_protocols
  attach_function :tls_config_set_ca_file, [:pointer, :string], :int
  # TODO: tls_config_set_ca_path
  # TODO: tls_config_set_ca_mem
  attach_function :tls_config_set_cert_file, [:pointer, :string], :int
  # TODO: tls_config_set_cert_mem
  attach_function :tls_config_set_ciphers, [:pointer, :string], :int
  # TODO: tls_config_set_dheparams
  # TODO: tls_config_set_ecdhecurve
  attach_function :tls_config_set_key_file, [:pointer, :string], :int
  # TODO: tls_config_set_key_mem
  attach_function :tls_config_set_protocols, [:pointer, :uint], :void
  # TODO: tls_config_set_verify_depth
  # TODO: tls_config_clear_keys
  # TODO: tls_config_insecure_noverifycert
  # TODO: tls_config_insecure_noverifyname
  # TODO: tls_config_verify
  # TODO: tls_load_file
  attach_function :tls_client, [], :pointer
  attach_function :tls_server, [], :pointer
  attach_function :tls_configure, [:pointer, :pointer], :int
  # TODO: tls_reset
  attach_function :tls_close, [:pointer], :int
  attach_function :tls_free, [:pointer], :void
  attach_function :tls_connect, [:pointer, :string, :string], :int
  # TODO: tls_connect_fds
  # TODO: tls_connect_servername
  # TODO: tls_connect_socket
  # TODO: tls_accept_fds
  attach_function :tls_accept_socket, [:pointer, :pointer, :int], :int
  attach_function :tls_read, [:pointer, :pointer, :size_t, :pointer], :int
  attach_function :tls_write, [:pointer, :pointer, :size_t, :pointer], :int
end
end
