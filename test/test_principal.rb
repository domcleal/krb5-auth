########################################################################
# test_principal.rb
#
# Test suite for the Krb5Auth::Krb5::Principal class.
########################################################################
require 'rubygems'
gem 'test-unit'

require 'open3'
require 'test/unit'
require 'krb5_auth'

class TC_Krb5_Principal < Test::Unit::TestCase
  def setup
    @princ = Krb5Auth::Krb5::Keytab.new
  end

  test "name basic functionality" do
    assert_respond_to(@princ, :name)
    assert_nothing_raised{ @princ.name }
  end

  test "expire_time basic functionality" do
    assert_respond_to(@princ, :expire_time)
    assert_nothing_raised{ @princ.expire_time }
  end

  test "last_password_change basic functionality" do
    assert_respond_to(@princ, :last_password_change)
    assert_nothing_raised{ @princ.last_password_change }
  end

  test "password_expiration" do
    assert_respond_to(@princ, :password_expiration)
    assert_nothing_raised{ @princ.password_expiration }
  end

  def teardown
    @princ = nil
  end
end
