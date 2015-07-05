require 'libtls/version'
require 'libtls/raw'
require 'libtls/client'
require 'libtls/server'

module LibTLS
  def self.init
    if LibTLS::Raw.tls_init < 0
      raise "tls_init failed"
    end
  end
end
