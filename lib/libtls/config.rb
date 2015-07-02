require 'libtls/raw'

module LibTLS
class Config
  VALID_SET_CONFIGS = %i(
    ca_file ca_path ca_mem cert_file cert_mem ciphers dheparams
    ecdhecurve key_file key_mem protocols verify_depth)

  def initialize(config_hash)
    @config_hash = config_hash
  end

  def as_raw
    @raw_config ||= buld_raw_config
  end

  def free
    LibTLS::Raw.tls_config_free(as_raw)
  end

  private

  def buld_raw_config
    if (raw = LibTLS::Raw.tls_config_new) == nil
      raise "tls_config_new failed"
    end

    valid_config_hash.each do |key, value|
      ret = LibTLS::Raw.send("tls_config_set_#{key}", raw, *value)

      if ret && ret < 0
        raise "tls_config_set_#{key} failed"
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
