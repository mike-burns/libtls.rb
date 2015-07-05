# coding: utf-8
lib = File.expand_path('../lib', __FILE__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)
require 'libtls/version'

Gem::Specification.new do |spec|
  spec.name          = "libtls"
  spec.version       = LibTLS::VERSION
  spec.authors       = ["Mike Burns"]
  spec.email         = ["mike@mike-burns.com"]
  spec.summary       = %q{Bindings for libtls (libressl)}
  spec.description   = %q{TODO: Write a longer description. Optional.}
  spec.homepage      = ""
  spec.license       = "ISC"

  spec.files         = `git ls-files -z`.split("\x0")
  spec.executables   = spec.files.grep(%r{^bin/}) { |f| File.basename(f) }
  spec.test_files    = spec.files.grep(%r{^(test|spec|features)/})
  spec.require_paths = ["lib"]

  spec.add_dependency "ffi", "~> 1.2.0"
  spec.requirements << 'libtls'

  spec.add_development_dependency "bundler", "~> 1.6"
  spec.add_development_dependency "rake", "~> 10.0"
  spec.add_development_dependency "rspec"
end
