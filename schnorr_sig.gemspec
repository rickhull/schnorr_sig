Gem::Specification.new do |s|
  s.name = 'schnorr_sig'
  s.summary = "Schnorr signatures in Ruby, multiple implementations"
  s.description = "Pure ruby based on ECDSA gem; separate libsecp256k1 impl"
  s.authors = ["Rick Hull"]
  s.homepage = "https://github.com/rickhull/schnorr_sig"
  s.license = "LGPL-2.1-only"

  s.required_ruby_version = "~> 3.0"

  s.version = File.read(File.join(__dir__, 'VERSION')).chomp

  s.files = %w[schnorr_sig.gemspec VERSION README.md Rakefile]
  s.files += Dir['lib/**/*.rb']
  s.files += Dir['test/**/*.rb']
  # s.files += Dir['examples/**/*.rb']

  s.add_dependency "ecdsa_ext", "~> 0"
end
