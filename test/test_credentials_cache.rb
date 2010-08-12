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

class TC_Krb5_Credentials_Cache < Test::Unit::TestCase
  def setup
    @princ  = Etc.getlogin + '@' + Krb5Auth::Krb5.new.default_realm
    @ccache = Krb5Auth::Krb5::CredentialsCache.new(@princ)
  end

  test "close method basic functionality" do
    assert_respond_to(@ccache, :close)
  end

  test "close method works as expected" do
    assert_nothing_raised{ @ccache.close }
  end

  test "calling close multiple times on the same object does not raise an error" do
    assert_nothing_raised{ @ccache.close }
    assert_nothing_raised{ @ccache.close }
    assert_nothing_raised{ @ccache.close }
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

  test "destroy method works as expected" do
    #assert_nothing_raised{ @ccache.destroy }
  end

  def teardown
    @princ  = nil
    @ccache = nil
  end
end
