########################################################################
# test_krb5.rb
#
# Test suite for the Krb5Auth::Krb5 class.
########################################################################
require 'test/unit'
require 'krb5_auth'

class TC_Krb5 < Test::Unit::TestCase
  def setup
    @krb5 = Krb5Auth::Krb5.new
  end

  def test_version
    assert_equal('0.8.0', Krb5Auth::Krb5::VERSION)
  end

  def teardown
    @krb5.close
  end
end
