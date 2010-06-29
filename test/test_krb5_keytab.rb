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

# TODO: We need to create a temporary keytab that we can use for
# testing purposes.

class TC_Krb5_Keytab < Test::Unit::TestCase
  def setup
    @file = "WRFILE:/home/dberger/dberger.keytab"
    @keytab = Krb5Auth::Krb5::Keytab.new
    @name = nil
  end

  test "constructor takes an optional name" do
    assert_nothing_raised{ @keytab = Krb5Auth::Krb5::Keytab.new("FILE:/usr/local/var/keytab") }
    assert_nothing_raised{ @keytab = Krb5Auth::Krb5::Keytab.new("FILE:/bogus/keytab") }
  end

  test "keytab name must be a string" do
    assert_raise(TypeError){ Krb5Auth::Krb5::Keytab.new(1) }
  end

  test "default_name basic functionality" do
    assert_respond_to(@keytab, :default_name)
    assert_nothing_raised{ @keytab.default_name }
    assert_kind_of(String, @keytab.default_name)
  end

  test "close basic functionality" do
    assert_respond_to(@keytab, :close)
    assert_nothing_raised{ @keytab.close }
    assert_boolean(@keytab.close)
  end

  test "each basic functionality" do
    assert_nothing_raised{ @keytab = Krb5Auth::Krb5::Keytab.new(@file) }
    assert_respond_to(@keytab, :each)
    assert_nothing_raised{ @keytab.each{} }
  end

  test "next entry yields a name" do
    array = []
    assert_nothing_raised{ @keytab = Krb5Auth::Krb5::Keytab.new(@file) }
    assert_nothing_raised{ @keytab.each{ |entry| array << entry } }
    assert_kind_of(String, array[0])
    assert_true(array.size > 1)
  end

  def teardown
    @keytab.close
    @keytab = nil
  end
end
