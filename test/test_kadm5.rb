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
  def self.startup
    @@info = DBI::DBRC.new('test-kerberos')
    ENV['KRB5_CONFIG'] = @@info.driver
  end

  def setup
    @user = @@info.user
    @pass = @@info.passwd
    @kadm = nil
    @struct = nil
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

  test "set_password basic functionality" do
    @kadm5 = Krb5Auth::Kadm5.new(@user, @pass)
    assert_respond_to(@kadm5, :set_password)
  end

  test "set_password requires two arguments" do
    @kadm5 = Krb5Auth::Kadm5.new(@user, @pass)
    assert_raise(ArgumentError){ @kadm5.set_password }
    assert_raise(ArgumentError){ @kadm5.set_password('user') }
    assert_raise(ArgumentError){ @kadm5.set_password('user', 'xxx', 'yyy') }
  end

  test "set_password requires string arguments" do
    @kadm5 = Krb5Auth::Kadm5.new(@user, @pass)
    assert_raise(TypeError){ @kadm5.set_password('user',2) }
    assert_raise(TypeError){ @kadm5.set_password(1, 'xxxx') }
  end

  test "create_principal basic functionality" do
    @kadm = Krb5Auth::Kadm5.new(@user, @pass)
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

  test "get_principal basic functionality" do
    assert_nothing_raised{ @kadm = Krb5Auth::Kadm5.new(@user, @pass) }
    assert_respond_to(@kadm, :get_principal)
  end

  test "get_principal returns a Struct::Principal object" do
    assert_nothing_raised{ @kadm = Krb5Auth::Kadm5.new(@user, @pass) }
    assert_nothing_raised{ @kadm.create_principal("zztop", "changeme") }
    assert_nothing_raised{ @struct = @kadm.get_principal("zztop") }
    assert_kind_of(Struct::Principal, @struct)
  end

  test "get_principal requires a string argument" do
    assert_nothing_raised{ @kadm = Krb5Auth::Kadm5.new(@user, @pass) }
    assert_raise(TypeError){ @kadm.get_principal(1) }
  end

  test "get_principal requires one and only one argument" do
    assert_nothing_raised{ @kadm = Krb5Auth::Kadm5.new(@user, @pass) }
    assert_raise(ArgumentError){ @kadm.get_principal }
    assert_raise(ArgumentError){ @kadm.get_principal(@user, @user) }
  end

  test "principal struct members" do
    @struct = Struct::Principal.new
    assert_respond_to(@struct, :principal)
    assert_respond_to(@struct, :princ_expire_time)
    assert_respond_to(@struct, :last_pwd_change)
    assert_respond_to(@struct, :pw_expiration)
    assert_respond_to(@struct, :max_life)
    assert_respond_to(@struct, :attributes)
    assert_respond_to(@struct, :mod_name)
    assert_respond_to(@struct, :mod_date)
    assert_respond_to(@struct, :kvno)
    assert_respond_to(@struct, :policy)
    assert_respond_to(@struct, :aux_attributes)
    assert_respond_to(@struct, :max_renewable_life)
    assert_respond_to(@struct, :last_success)
    assert_respond_to(@struct, :last_failed)
    assert_respond_to(@struct, :fail_auth_count)
  end

  def teardown
    @kadm.delete_principal("zztop") rescue nil
    @user   = nil
    @pass   = nil
    @kadm   = nil
    @struct = nil
  end

  def self.shutdown
    @@info = nil
  end
end
