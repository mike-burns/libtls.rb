require 'rspec'
require 'libtls'
require 'support/fixtures'

describe 'a libtls client' do
  it 'reads data via a TLS connection' do
    config = {
      protocols: LibTLS::Raw::TLS_PROTOCOL_TLSv1_2,
      ca_file: fixture_filename('mike-burns.pem')
    }

    content = nil
    LibTLS::Client.new(configure: config) do |client|
      content = client.connect("mike-burns.com", 443) do |c|
        c.write(http_get("mike-burns.com"))
        c.read
      end
    end

    expect(content[0..14]).to eq "HTTP/1.1 200 OK"
  end

  private

  def http_get(hostname)
    "GET / HTTP/1.1\r\nUser-Agent: libtls.rb/0.1\r\nHost: #{hostname}\r\n\r\n"
  end
end
