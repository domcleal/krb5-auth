#######################################################################
# test_credentials_cache.rb
#
# Tests for the Krb5Auth::Krb5::Credentials class.
#######################################################################
require 'rubygems'
gem 'test-unit'

require 'etc'
require 'test/unit'
require 'krb5_auth'
require 'open3'

class TC_Krb5_Credentials_Cache < Test::Unit::TestCase
  def setup
    @princ  = Etc.getlogin + '@' + Krb5Auth::Krb5.new.default_realm
    @ccache = Krb5Auth::Krb5::CredentialsCache.new(@princ)
  end

  # Helper method that uses the command line utility for external verification
  def cache_found
    found = true

    Open3.popen3('klist') do |stdin, stdout, stderr|
      found = false unless stderr.gets.nil?
    end

    found
  end

  test "close method basic functionality" do
    assert_respond_to(@ccache, :close)
  end

  # We call the constructor here again to ensure the cache hasn't been
  # destroyed somewhere else in the test suite.
  test "close method does not delete credentials cache" do
    @ccache = Krb5Auth::Krb5::CredentialsCache.new(@princ)
    assert_nothing_raised{ @ccache.close }
    assert_true(cache_found)
  end

  test "calling close multiple times on the same object does not raise an error" do
    assert_nothing_raised{ @ccache.close }
    assert_nothing_raised{ @ccache.close }
    assert_nothing_raised{ @ccache.close }
  end

  test "calling a method on a closed object raises an error" do
    @ccache.close
    assert_raise(Krb5Auth::Krb5::Exception){ @ccache.default_name } 
  end

  test "calling constructor without an argument raises an error" do
    assert_raise(ArgumentError){ Krb5Auth::Krb5::CredentialsCache.new }
  end

  test "calling constructor with a non string argument raises an error" do
    assert_raise(TypeError){ Krb5Auth::Krb5::CredentialsCache.new(true) }
  end

  test "default_name basic functionality" do
    assert_respond_to(@ccache, :default_name)
    assert_nothing_raised{ @ccache.default_name }
  end

  test "default_name returns a string" do
    assert_kind_of(String, @ccache.default_name)
  end

  test "destroy method basic functionality" do
    assert_respond_to(@ccache, :destroy)
  end

  test "destroy method deletes credentials cache" do
    assert_nothing_raised{ @ccache.destroy }
    assert_false(cache_found)
  end

  test "delete is an alias for destroy" do
    assert_respond_to(@ccache, :delete)
    assert_alias_method(@ccache, :destroy, :delete)
  end

  test "calling a method on a destroyed object raises an error" do
    @ccache.destroy
    assert_raise(Krb5Auth::Krb5::Exception){ @ccache.default_name } 
  end

  test "destroy method does not accept any arguments" do
    assert_raise(ArgumentError){ @ccache.destroy(true) }
  end

  def teardown
    @princ  = nil
    @ccache = nil
  end
end
