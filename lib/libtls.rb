require 'libtls/version'
require 'libtls/raw'
require 'libtls/client'
require 'libtls/server'

module LibTLS
  ### TODO: FFI::ConstGenerator 
  PROTOCOL_ALL = 2 | 4 | 8
  READ_AGAIN = -2
  WRITE_AGAIN = -3

  def self.init
    if LibTLS::Raw.tls_init < 0
      raise "tls_init failed"
    end
  end
end
