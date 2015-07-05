# libtls for Ruby

This is a set of libtls bindings for Ruby, plus a nice object-oriented layer
atop the bindings.

## Installation

This gem depends on the libtls library. Make sure you either run OpenBSD or
have [libressl-portable] installed.

Once libtls itself is installed, add this line to your application's Gemfile:

```ruby
gem 'libtls'
```

And then execute:

    $ bundle

Or install it yourself as:

    $ gem install libtls

[libressl-portable]: http://www.libressl.org/releases.html

## Usage

This library provides the API on two levels: the raw C functions, and a nice
object-oriented layer atop it.

Below you will find an introduction, but a more in-depth reference can be found
on [Rubydoc][].

[Rubydoc]: http://www.rubydoc.info/gems/libtls

### Raw

The raw functions are as follows; see `tls_init`(3) for more information on what
they do:

- `LibTLS::Raw.tls_init`
- `LibTLS::Raw.tls_error`
- `LibTLS::Raw.tls_config_new`
- `LibTLS::Raw.tls_config_free`
- `LibTLS::Raw.tls_config_parse_protocols`
- `LibTLS::Raw.tls_config_set_ca_file`
- `LibTLS::Raw.tls_config_set_ca_path`
- `LibTLS::Raw.tls_config_set_ca_mem`
- `LibTLS::Raw.tls_config_set_cert_file`
- `LibTLS::Raw.tls_config_set_cert_mem`
- `LibTLS::Raw.tls_config_set_ciphers`
- `LibTLS::Raw.tls_config_set_dheparams`
- `LibTLS::Raw.tls_config_set_ecdhecurve`
- `LibTLS::Raw.tls_config_set_key_file`
- `LibTLS::Raw.tls_config_set_key_mem`
- `LibTLS::Raw.tls_config_set_protocols`
- `LibTLS::Raw.tls_config_set_verify_depth`
- `LibTLS::Raw.tls_config_clear_keys`
- `LibTLS::Raw.tls_config_insecure_noverifycert`
- `LibTLS::Raw.tls_config_insecure_noverifyname`
- `LibTLS::Raw.tls_config_verify`
- `LibTLS::Raw.tls_load_file`
- `LibTLS::Raw.tls_client`
- `LibTLS::Raw.tls_server`
- `LibTLS::Raw.tls_configure`
- `LibTLS::Raw.tls_reset`
- `LibTLS::Raw.tls_close`
- `LibTLS::Raw.tls_free`
- `LibTLS::Raw.tls_connect`
- `LibTLS::Raw.tls_connect_fds`
- `LibTLS::Raw.tls_connect_servername`
- `LibTLS::Raw.tls_connect_socket`
- `LibTLS::Raw.tls_accept_fds`
- `LibTLS::Raw.tls_accept_socket`
- `LibTLS::Raw.tls_read`
- `LibTLS::Raw.tls_write`

Of particular note are those functions which take a pointer (`tls_read`,
`tls_write`, `tls_accept_socket`, and others). These must have an instance of
`FFI::MemoryPointer` passed to them:

```ruby
FFI::MemoryPointer.new(:size_t) do |outlen|
  FFI::MemoryPointer.new(:uchar, 1024, true) do |buf|

    ret = LibTLS::Raw.tls_read(client, buf, 1024, outlen)

    if ret < 0
      raise "tls_read: #{LibTLS::Raw.tls_error(client)}"
    end

  end
end
```

Additionally, instance of Ruby's `Socket` object must be converted to their
file descriptor before interfacing with the C function. The `tls_accept_socket`
function combines the `FFI::MemoryPointer` requirement with this file
descriptor requirement:

```ruby
  cctx_ptr = FFI::MemoryPointer.new(:pointer)

  if tls_accept_socket(server, cctx_ptr, socket.fileno) == -1
    raise "tls_accept_socket: #{LibTLS::Raw.tls_error(server)}"
  end

  cctx = cctx_ptr.read_pointer
```

Constants from `tls.h` are manually re-exposed under the `LibTLS::Raw`
namespace:

- `LibTLS::Raw::TLS_API`
- `LibTLS::Raw::TLS_PROTOCOL_TLSv1_0`
- `LibTLS::Raw::TLS_PROTOCOL_TLSv1_1`
- `LibTLS::Raw::TLS_PROTOCOL_TLSv1_2`
- `LibTLS::Raw::TLS_PROTOCOL_TLSv1`
- `LibTLS::Raw::TLS_PROTOCOLS_ALL`
- `LibTLS::Raw::TLS_PROTOCOLS_DEFAULT`
- `LibTLS::Raw::TLS_READ_AGAIN`
- `LibTLS::Raw::TLS_WRITE_AGAIN`

### Object-Oriented Wrapper

An object-oriented wrapper is provided. Here is an example of a client:

```ruby
# Get the contents of the Web page hosted at https://#{hostname}:443#{path} .
def get(hostname, path)
  # The return value: nil, or a string.
  content = nil

  # TLS configuration. The key is formed from the series of tls_config_set_*
  # functions; the value is either the scalar value (int or string), or an
  # array of the multiple values. For example, ca_mem takes an array with the
  # FFI::MemoryPointer and the length of that pointer.
  config = {
    ciphers: "DES-CBC3-SHA",
    protocols: LibTLS::Raw::TLS_PROTOCOLS_ALL
  }

  # Create a new libtls client. The block is then immediately run, and then the
  # memory free'd.
  LibTLS::Client.new(configure: config) do |client|
    # Connect to the server on port 443. When the block finishes, disconnect.
    content = client.connect("mike-burns.com", 443) do |c|
      # Send a string to the server; in this case, a HTTP request.
      c.write(http_get(hostname, path))
      # Read all the data from the server, and return it. The return value of
      # this block is the return value of Client#connect.
      c.read
    end
  end

  # Return the content.
  content
end

# Generate a HTTP request string.
def http_get(hostname, path)
  ["GET #{path} HTTP/1.1",
   "User-Agent: libtls.rb/0.1",
   "Host: #{hostname}"].join("\r\n") +
   "\r\n"
end
```

And here is an example of a simple echo server:

```ruby
# Reply to the socket's clients with their own string.
def echo_server(socket)
  # Encrypt communications using the key and cert as generated by e.g.
  # LibreSSL.
  config = {
      key_file: "thekey.key",
      cert_file: "thecert.crt"
  }

  # Create and configure a new server object. The block is then immediately
  # run, and then the memory is free'd.
  LibTLS::Server.new(configure: config) do |server|
    # Block until a client connects on client_socket.
    client_socket, _ = socket.accept

    # Loop forever; this allows another client to connect after this one.
    loop do
      # Handle the TLS handshake on the client socket. This takes a block,
      # which is run immediately after the handshake has completed
      # successfully. After the block finishes, disconnect and clean up. The
      # block takes an opened client object.
      server.accept(client_socket) do |c|
        # Loop so that the client can write until they disconnect.
        loop do
          # Read the entirety of the client's string.
          str = c.read
          # Write exactly what the client sent.
          c.write(str)
        end
      end
    end
  end
end
```

The underlying `struct tls *` object is exposed through the `#ctx` method; it
can be passed to any `LibTLS::Raw` method, for example.

These methods can raise instances of `LibTLS::UnknownCError` and
`LibTLS::CError`. Instances of the first are raised when we do not have access
to the underlying issue, and instances of the second attempt to include the
error string from libtls.

## Contributing

As contributors and maintainers of this project, we will respect all people
who contribute in any fashion. We are committed to making participation in this
project a harassment-free experience for everyone, regardless of who they are.

The project maintainers have the right and responsibility to remove, edit, or
reject comments, commits, code, wiki edits, issues, and other contributions
that are not aligned to this code of conduct. Project maintainers who do not
follow the code of conduct may be removed from the project team.

Instances of unacceptable behavior may be reported by [opening an
issue][issues] or contacting [Mike Burns](mailto:mike@mike-burns.com)
([PGP key][Mike PGP key]).

[issues]: https://github.com/mike-burns/libtls.rb/issues
[Mike PGP key]: http://pgp.mit.edu/pks/lookup?op=get&search=0x3E6761F72846B014

### To contribute a feature

1. Fork it ( https://github.com/mike-burns/libtls.rb/fork )
2. Make sure the tests pass (`rake`)
3. Create your feature branch (`git checkout -b my-new-feature`)
4. Commit your changes (`git commit -am 'Add some feature'`)
5. Push to the branch (`git push origin my-new-feature`)
6. Make sure the tests pass (`rake`)
7. Make sure documentation is complete (`yard`)
8. Create a new Pull Request

*Feature requests without patches will be closed*.

### To report a security issue

If the issue should be kept quiet for security reasons, email
[Mike Burns](mailto:mike@mike-burns.com) directly. His PGP key id is
[0x2846b014][Mike PGP key], fingerprint:

    5FD8 2CE6 A646 3285 538F
    C3A5 3E67 61F7 2846 B014

## Credits

libtls for Ruby is by [Mike Burns]. It is released under the
[ISC license][LICENSE].

It would have been impossible to make this library so quickly without the
knowledge gained on [erltls] with [Rebecca Meritz].

GNU help was provided by [Matt Horan].

The [ffi] gem has also proven crucial to this project; thanks to
[Wayne Meissner, et al.][ffi credits], for their amazing work on that.

The code of conduct is adapted from the [Contributor Covenant],
[version 1.1.0][coc110].

[Donate to the OpenBSD Foundation][donate]. Without them, none of this would
exist.

[Mike Burns]: https://mike-burns.com
[Rebecca Meritz]: http://rebecca.meritz.com/
[Matt Horan]: https://matthoran.com/
[LICENSE]: LICENSE
[donate]: http://www.openbsdfoundation.org/donations.html
[ffi]: https://github.com/ffi/ffi/wiki
[ffi credits]: https://github.com/ffi/ffi/#credits
[erltls]: https://github.com/meritz-burns/erltls
[Contributor Covenant]: http://contributor-covenant.org
[coc110]: http://contributor-covenant.org/version/1/1/0/
