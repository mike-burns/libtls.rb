# libtls for Ruby

This is a set of libtls bindings for Ruby, plus a nice OO layer atop the
bindings.

This is a work in progress. If you figure out how to use this, please
contribute back with documentation, bindings, and bug fixes.

## Installation

Add this line to your application's Gemfile:

```ruby
gem 'libtls'
```

And then execute:

    $ bundle

Or install it yourself as:

    $ gem install libtls

## Usage

This library provides the API on two levels: the raw C functions, and a nice OO
layer atop it.

### Raw

The raw functions are as follows; see `tls_init`(3) for more information on what
they do:

- `LibTLS::Raw.tls_init`
- `LibTLS::Raw.tls_client`
- `LibTLS::Raw.tls_close`
- `LibTLS::Raw.tls_connect`
- `LibTLS::Raw.tls_configure`
- `LibTLS::Raw.tls_config_new`
- `LibTLS::Raw.tls_config_set_ciphers`
- `LibTLS::Raw.tls_config_set_protocols`
- `LibTLS::Raw.tls_config_set_ca_file`
- `LibTLS::Raw.tls_config_free`
- `LibTLS::Raw.tls_free`
- `LibTLS::Raw.tls_write`
- `LibTLS::Raw.tls_read`
- `LibTLS::Raw.tls_error`

Of particular note are those functions which take a pointer (`tls_read` and
`tls_write`). These must have an instance of `FFI::MemoryPointer` passed to
them:

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

### OO

An object-oriented wrapper is provided. Here is an example, from the test
suite:

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
    protocols: LibTLS::PROTOCOL_ALL
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

## Contributing

1. Fork it ( https://github.com/mike-burns/libtls.rb/fork )
2. Make sure the tests pass (`rake`)
3. Create your feature branch (`git checkout -b my-new-feature`)
4. Commit your changes (`git commit -am 'Add some feature'`)
5. Push to the branch (`git push origin my-new-feature`)
6. Make sure the tests pass (`rake`)
7. Create a new Pull Request

## Authors

* [Mike Burns](https://mike-burns.com)

[Donate to the OpenBSD Foundation](http://www.openbsdfoundation.org/donations.html).

Released under the [ISC license][LICENSE].

[LICENSE]: LICENSE
