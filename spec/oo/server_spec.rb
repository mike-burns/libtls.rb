require 'rspec'
require 'socket'
require 'libtls'

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
  let(:port) { "3335" }
  let(:key_file) { fixture_filename("thekey.key") }
  let(:cert_file) { fixture_filename("thecert.crt") }
  let(:ca_file) { fixture_filename("theca.pem") }
  let(:msg) { "hello\r\n" }

  def echo_client(str)
    content = ""
    config = {
      protocols: LibTLS::PROTOCOL_ALL,
      ca_file: ca_file
    }

    LibTLS::Client.new(configure: config) do |client|
      begin
        content = client.connect(hostname, port) do |c|
          c.write(str)
          c.read
        end
      rescue RuntimeError ### TODO: change this when we support better exns
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

  def fixture_filename(fn)
    spec_path = File.expand_path('../../', __FILE__)
    File.join(spec_path, 'fixtures', fn)
  end
end
