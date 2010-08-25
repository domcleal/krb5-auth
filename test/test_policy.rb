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

  test 'pw_min_life basic functionality' do
    assert_respond_to(@policy, :pw_min_life)
    assert_nothing_raised{ @policy.pw_min_life }
  end

  test 'pw_max_life basic functionality' do
    assert_respond_to(@policy, :pw_max_life)
    assert_nothing_raised{ @policy.pw_max_life }
  end

  test 'pw_min_length basic functionality' do
    assert_respond_to(@policy, :pw_min_length)
    assert_nothing_raised{ @policy.pw_min_length }
  end

  test 'pw_min_classes basic functionality' do
    assert_respond_to(@policy, :pw_min_classes)
    assert_nothing_raised{ @policy.pw_min_classes }
  end

  test 'pw_history_num basic functionality' do
    assert_respond_to(@policy, :pw_history_num)
    assert_nothing_raised{ @policy.pw_history_num }
  end

  test 'policy_refcnt basic functionality' do
    assert_respond_to(@policy, :policy_refcnt)
    assert_nothing_raised{ @policy.policy_refcnt }
  end

  test 'pw_max_fail basic functionality' do
    assert_respond_to(@policy, :pw_max_fail)
    assert_nothing_raised{ @policy.pw_max_fail }
  end

  test 'pw_failcnt_interval basic functionality' do
    assert_respond_to(@policy, :pw_failcnt_interval)
    assert_nothing_raised{ @policy.pw_failcnt_interval }
  end

  test 'pw_lockout_duration basic functionality' do
    assert_respond_to(@policy, :pw_lockout_duration)
    assert_nothing_raised{ @policy.pw_lockout_duration }
  end

  def teardown
    @policy = nil
  end
end
