########################################################################
# test_krb5.rb
#
# Test suite for the Krb5Auth::Krb5 class.
########################################################################
require 'rubygems'
gem 'test-unit'

require 'test/unit'
require 'krb5_auth'

class TC_Krb5 < Test::Unit::TestCase
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

  test "change_password fails if there is no context" do
    notify("Oops, this segfaults at the moment. Needs fixing.")
  end

  def teardown
    @krb5.close
  end
end
