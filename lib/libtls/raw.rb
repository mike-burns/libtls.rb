require 'ffi'

module LibTLS
module Raw
  extend FFI::Library

  ffi_lib "libtls.so"

  attach_function :tls_init, [], :int
  attach_function :tls_client, [], :pointer
  attach_function :tls_close, [:pointer], :int
  attach_function :tls_connect, [:pointer, :string, :string], :int
  attach_function :tls_configure, [:pointer, :pointer], :int
  attach_function :tls_config_new, [], :pointer
  attach_function :tls_config_set_ciphers, [:pointer, :string], :int
  attach_function :tls_config_set_protocols, [:pointer, :uint], :void
  attach_function :tls_config_set_ca_file, [:pointer, :string], :int
  attach_function :tls_config_free, [:pointer], :void
  attach_function :tls_free, [:pointer], :void
  attach_function :tls_write, [:pointer, :pointer, :size_t, :pointer], :int
  attach_function :tls_read, [:pointer, :pointer, :size_t, :pointer], :int
  attach_function :tls_error, [:pointer], :string
end
end
