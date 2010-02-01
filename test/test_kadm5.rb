########################################################################
# test_kadm5.rb
#
# Tests for the Krb5Auth::Kadm5 class.
########################################################################
require 'rubygems'
gem 'test-unit'

require 'test/unit'
require 'dbi/dbrc'
require 'krb5_auth'

class TC_Krb5Auth_Kadm5 < Test::Unit::TestCase
  def setup
    @info = DBI::DBRC.new('kerberos')
    @user = @info.user
    @pass = @info.passwd
    @kadm = nil
  end

  test "constructor basic functionality" do
    assert_respond_to(Krb5Auth::Kadm5, :new)
  end

  test "constructor with valid user and password works as expected" do
    assert_nothing_raised{ Krb5Auth::Kadm5.new(@user, @pass) }
  end

  test "constructor with invalid user or password raises an error" do
    assert_raise(Krb5Auth::Kadm5::Exception){ Krb5Auth::Kadm5.new(@user, 'bogus') }
    assert_raise(Krb5Auth::Kadm5::Exception){ Krb5Auth::Kadm5.new('bogus', @pass) }
  end

  test "create_principal basic functionality" do
    assert_nothing_raised{ @kadm = Krb5Auth::Kadm5.new(@user, @pass) }
    assert_respond_to(@kadm, :create_principal)
  end

  test "create_principal creates a user as expected" do
    assert_nothing_raised{ @kadm = Krb5Auth::Kadm5.new(@user, @pass) }
    assert_nothing_raised{ @kadm.create_principal("zztop", "changeme") }
  end

  test "create_principal requires two arguments" do
    assert_nothing_raised{ @kadm = Krb5Auth::Kadm5.new(@user, @pass) }
    assert_raise(ArgumentError){ @kadm.create_principal }
    assert_raise(ArgumentError){ @kadm.create_principal(@user) }
    assert_raise(ArgumentError){ @kadm.create_principal(@user, @pass, @pass) }
  end

  test "attempting to create a principal that already exists raises an error" do
    assert_nothing_raised{ @kadm = Krb5Auth::Kadm5.new(@user, @pass) }
    assert_nothing_raised{ @kadm.create_principal("zztop", "changeme") }
    assert_raise(Krb5Auth::Kadm5::Exception){ @kadm.create_principal("zztop", "changeme") }
  end

  test "delete_principal basic functionality" do
    assert_nothing_raised{ @kadm = Krb5Auth::Kadm5.new(@user, @pass) }
    assert_respond_to(@kadm, :delete_principal)
  end

  test "delete_principal works as expected" do
    assert_nothing_raised{ @kadm = Krb5Auth::Kadm5.new(@user, @pass) }
    assert_nothing_raised{ @kadm.create_principal("zztop", "changeme") }
    assert_nothing_raised{ @kadm.delete_principal("zztop") }
  end

  test "delete_principal takes one argument and only one argument" do
    assert_nothing_raised{ @kadm = Krb5Auth::Kadm5.new(@user, @pass) }
    assert_raise(ArgumentError){ @kadm.delete_principal }
    assert_raise(ArgumentError){ @kadm.delete_principal(@user, @pass) }
  end

  def teardown
    @kadm.delete_principal("zztop") rescue nil
    @info = nil
    @user = nil
    @pass = nil
    @kadm = nil
  end
end
