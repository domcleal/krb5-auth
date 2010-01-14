require 'rubygems'

spec = Gem::Specification.new do |gem|
  gem.name       = 'krb5-auth'
  gem.version    = '0.7.1'
  gem.author     = 'Daniel Berger'
  gem.license    = 'Artistic 2.0'
  gem.email      = 'djberg96@gmail.com'
  gem.homepage   = 'http://github.com/djberg96/krb5-auth'
  gem.platform   = Gem::Platform::RUBY
  gem.summary    = 'A Ruby interface for the the Kerberos library'
  gem.has_rdoc   = true
  gem.test_files = Dir['test/test*']
  gem.extensions = ['ext/extconf.rb']
  gem.files      = Dir['**/*'].reject{ |f| f.include?('git') }
  
  gem.rubyforge_project = 'krb5-auth'
  gem.extra_rdoc_files = ['README', 'CHANGES', 'MANIFEST', 'ext/rkerberos.c']
  
  gem.add_development_dependency('test-unit', '>= 2.0.6')
   
  gem.description = <<-EOF
    The krb5-auth library is an interface for the Kerberos 5 network
    authentication protocol. It wraps the Kerberos C API.
  EOF
end
