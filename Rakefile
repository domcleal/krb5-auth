require 'rake'
require 'rake/testtask'
require 'rake/clean'
require 'rbconfig'

desc 'Clean any build files and .gem files'
task :clean do
  Dir.chdir('ext') do
    rm_rf 'conftest.dSYM' if File.exists?('conftest.dSYM')
    sh 'make distclean' rescue nil
  end
  Dir['*.gem'].each{ |f| File.delete(f) }
  rm_rf('lib')
end

desc 'Build the library'
task :build => [:clean] do
  Dir.chdir('ext') do
    ruby 'extconf.rb'
    sh 'make'
  end
end

desc 'Create a tarball of the source'
task :archive do
  Dir['*.tar*'].each{ |f| File.delete(f) }
  sh "git archive --format=tar HEAD > krb5-auth.tar"
  sh "gzip krb5-auth.tar"
end

namespace :gem do
  desc 'Delete any existing gem files in the project.'
  task :clean do
    Dir['*.gem'].each{ |f| File.delete(f) } 
    rm_rf 'lib'
  end 

  desc 'Create the gem'
  task :create => [:clean] do
    spec = eval(IO.read('krb5-auth.gemspec'))
    Gem::Builder.new(spec).build
  end

  desc 'Install the gem'
  task :install => [:build] do
    file = Dir["*.gem"].first
    sh "gem install #{file}" 
  end

  desc 'Create a binary gem'
  task :binary => [:clean] do
    make = Config::CONFIG['host_os'] =~ /win32|windows|msdos|mswin/i ? 'nmake' : 'make'

    Dir.chdir('ext') do
      ruby 'extconf.rb'
      sh make
    end

    mkdir 'lib'
    file = File.join('ext', 'krb5_auth.' + Config::CONFIG['DLEXT'])
    cp file, 'lib'

    spec = eval(IO.read('krb5-auth.gemspec'))
    spec.platform = Gem::Platform::CURRENT
    spec.extensions = nil
    spec.files = spec.files.reject{ |f| f.include?('ext') }

    Gem::Builder.new(spec).build
  end
end

namespace 'test' do
  Rake::TestTask.new('all') do |t|
    task :all => :build
    t.libs << 'ext' 
    t.warning = true
    t.verbose = true
  end

  Rake::TestTask.new('krb5') do |t|
    task :krb5 => :build
    t.libs << 'ext' 
    t.test_files = FileList['test/test_krb5.rb']
    t.warning = true
    t.verbose = true
  end

  Rake::TestTask.new('kadm5') do |t|
    task :kadm5 => :build
    t.libs << 'ext' 
    t.test_files = FileList['test/test_kadm5.rb']
    t.warning = true
    t.verbose = true
  end
end
