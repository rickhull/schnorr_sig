require 'rake/testtask'

Rake::TestTask.new :test do |t|
  t.pattern = "test/*.rb"
  t.warning = true
end

task default: :test

desc "Run type checks (RBS + Steep)"
task :steep do
  ENV['RUBYOPT'] = ENV['RUBYOPT'].sub('--enable-frozen-string-literal', '')
  bindir = Dir[File.join(ENV['HOME'], '.local/share/gem/ruby/*/bin')].last
  bindir ? sh("#{File.join(bindir, 'steep')} check") : puts("can't find steep")
end

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
