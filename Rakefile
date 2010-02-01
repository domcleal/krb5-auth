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
end

desc 'Build the library'
task :build => [:clean] do
  Dir.chdir('ext') do
    ruby 'extconf.rb'
    sh 'make'
  end
end

namespace :gem do
  desc 'Build the gem'
  task :build do
    spec = eval(IO.read('krb5-auth.gemspec'))
    Gem::Builder.new(spec).build
  end

  task 'Install the gem'
  task :install => [:build] do
    file = Dir["*.gem"].first
    sh "gem install #{file}" 
  end
end

Rake::TestTask.new('test') do |t|
  task :test => :build
  t.libs << 'ext' 
  t.warning = true
  t.verbose = true
end
