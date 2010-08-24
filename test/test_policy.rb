########################################################################
# test_policy.rb
#
# Tests for the Krb5Auth::Kadm5::Policy class.
########################################################################
require 'rubygems'
gem 'test-unit'

require 'test/unit'
require 'krb5_auth'

class TC_Kadm5_Policy < Test::Unit::TestCase
  def setup
    @policy = Krb5Auth::Kadm5::Policy.new('test')
  end

  test 'policy name basic functionality' do
    assert_respond_to(@policy, :policy)
  end

  test 'policy name alias' do
    assert_respond_to(@policy, :name)
    assert_alias_method(@policy, :name, :policy)
  end

  def teardown
    @policy = nil
  end
end
