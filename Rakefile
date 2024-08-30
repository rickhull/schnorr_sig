require 'rake/testtask'

Rake::TestTask.new :test do |t|
  t.test_files = [
    'test/pure.rb',
    'test/schnorr_sig.rb',
    'test/vectors.rb',
    'test/vectors_extra.rb',
  ]
  t.warning = true
end

task default: :test

begin
  require 'buildar'

  Buildar.new do |b|
    b.gemspec_file = 'schnorr_sig.gemspec'
    b.version_file = 'VERSION'
    b.use_git = true
  end
rescue LoadError
  warn "buildar tasks unavailable"
end
