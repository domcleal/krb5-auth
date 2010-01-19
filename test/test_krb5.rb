########################################################################
# test_krb5.rb
#
# Test suite for the Krb5Auth::Krb5 class.
########################################################################
require 'rubygems'
gem 'test-unit'

require 'open3'
require 'test/unit'
require 'krb5_auth'

class TC_Krb5 < Test::Unit::TestCase
  def self.startup
    @@cache_found = true
    Open3.popen3('klist') do |stdin, stdout, stderr|
      @@cache_found = false unless stderr.gets.nil?
    end
  end

  def setup
    @krb5 = Krb5Auth::Krb5.new
  end

  test "version constant" do
    assert_equal('0.8.0', Krb5Auth::Krb5::VERSION)
  end

  test "get_default_realm basic functionality" do
    assert_respond_to(@krb5, :get_default_realm)
    assert_nothing_raised{ @krb5.get_default_realm }
    assert_kind_of(String, @krb5.get_default_realm)
  end

  test "get_default_realm takes no arguments" do
    assert_raise(ArgumentError){ @krb5.get_default_realm('localhost') }
  end

  test "get_init_creds_password basic functionality" do
    assert_respond_to(@krb5, :get_init_creds_password)
  end

  test "get_init_creds_password requires two arguments" do
    assert_raise(ArgumentError){ @krb5.get_init_creds_password }
    assert_raise(ArgumentError){ @krb5.get_init_creds_password('test') }
  end

  test "get_init_creds_password requires string arguments" do
    assert_raise(TypeError){ @krb5.get_init_creds_password(1, 2) }
    assert_raise(TypeError){ @krb5.get_init_creds_password('test', 1) }
  end

  test "change_password basic functionality" do
    assert_respond_to(@krb5, :change_password)
  end

  test "change_password requires two arguments" do
    assert_raise(ArgumentError){ @krb5.change_password }
    assert_raise(ArgumentError){ @krb5.change_password('XXXXXXXX') }
  end

  test "change_password requires two strings" do
    assert_raise(TypeError){ @krb5.change_password(1, 'XXXXXXXX') }
    assert_raise(TypeError){ @krb5.change_password('XXXXXXXX', 1) }
  end

  test "change_password fails if there is no context or principal" do
    assert_raise(Krb5Auth::Krb5::Exception){ @krb5.change_password("XXX", "YYY") }
    assert_raise_message('no principal has been established'){ @krb5.change_password("XXX", "YYY") }
  end

  test "get_default_principal basic functionality" do
    assert_respond_to(@krb5, :get_default_principal)
  end

  test "get_default_principal returns a string if cache found" do
    omit_unless(@@cache_found, "No credentials cache found, skipping")
    assert_nothing_raised{ @krb5.get_default_principal }
    assert_kind_of(String, @krb5.get_default_principal)
  end

  test "get_default_principal raises an error if no cache is found" do
    omit_if(@@cache_found, "Credential cache found, skipping")
    assert_raise(Krb5Auth::Krb5::Exception){ @krb5.get_default_principal }
  end

  def teardown
    @krb5.close
    @krb5 = nil
  end

  def self.shutdown
    @@cache_found = nil
  end
end
