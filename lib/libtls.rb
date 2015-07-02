require 'libtls/version'
require 'libtls/raw'
require 'libtls/client'

module LibTLS
  PROTOCOL_ALL = 2 | 4 | 8

  def self.init
    if LibTLS::Raw.tls_init < 0
      raise "tls_init failed"
    end
  end
end
