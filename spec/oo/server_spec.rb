require 'rspec'
require 'socket'
require 'libtls'
require 'support/fixtures'

describe 'a libtls server' do
  before :each do
    @socket = create_socket_for_client(hostname, port)
  end

  after :each do
    @client_socket && @client_socket.close
    @socket && @socket.close
  end

  it 'sends data via a TLS connection' do
    config = {
      key_file: key_file,
      cert_file: cert_file
    }

    fork do
      @client_socket, _ = @socket.accept

      LibTLS::Server.new(configure: config) do |server|
        server.accept(@client_socket) do |c|
          str = c.read
          c.write(str)
        end
      end
    end
    sleep 1

    content = echo_client(msg)

    expect(content).to eq (msg)
  end

  private

  let(:hostname) { "localhost" }
  let(:port) { "3334" }
  let(:key_file) { fixture_filename("thekey.key") }
  let(:cert_file) { fixture_filename("thecert.crt") }
  let(:ca_file) { fixture_filename("theca.pem") }
  let(:msg) { "hello\r\n" }

  def echo_client(str)
    content = ""
    config = {
      protocols: LibTLS::Raw::TLS_PROTOCOLS_ALL,
      ca_file: ca_file
    }

    LibTLS::Client.new(configure: config) do |client|
      begin
        content = client.connect(hostname, port) do |c|
          c.write(str)
          c.read
        end
      rescue LibTLS::CError
      end
    end

    content
  end

  def create_socket_for_client(hostname, port)
    sock = Socket.new(Socket::Constants::AF_INET,
                      Socket::Constants::SOCK_STREAM,
                      0)
    sin = Socket.pack_sockaddr_in(port, hostname)
    sock.bind(sin)
    sock.listen(1)

    sock
  end
end
