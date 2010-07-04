########################################################################
# test_kadm5.rb
#
# Tests for the Krb5Auth::Kadm5 class.
#
# This test suite requires that you have an entry in your .dbrc file
# for 'test-kerberos' which includes an admin principal, password and
# optional $KRB5_CONFIG file.
########################################################################
require 'rubygems'
gem 'test-unit'

require 'test/unit'
require 'dbi/dbrc'
require 'krb5_auth'

class TC_Krb5Auth_Kadm5 < Test::Unit::TestCase
  def self.startup
    @@info = DBI::DBRC.new('test-kerberos')
    ENV['KRB5_CONFIG'] = @@info.driver || ENV['KRB5_CONFIG'] || '/etc/krb5.conf'
  end

  def setup
    @user = @@info.user
    @pass = @@info.passwd
    @kadm = nil
    @struct = nil
    @test_princ = "zztop"
  end

  test "constructor basic functionality" do
    assert_respond_to(Krb5Auth::Kadm5, :new)
  end

  test "constructor with valid user and password works as expected" do
    assert_nothing_raised{ @kadm = Krb5Auth::Kadm5.new(@user, @pass) }
  end

  test "constructor with invalid user or password raises an error" do
    assert_raise(Krb5Auth::Kadm5::Exception){ Krb5Auth::Kadm5.new(@user, 'bogus') }
    assert_raise(Krb5Auth::Kadm5::Exception){ Krb5Auth::Kadm5.new('bogus', @pass) }
  end

  test "constructor with invalid user or password raises a specific error message" do
    assert_raise_message('kadm5_init_with_password: Incorrect password'){ Krb5Auth::Kadm5.new(@user, 'bogus') }
    assert_raise_message('kadm5_init_with_password: Client not found in Kerberos database'){ Krb5Auth::Kadm5.new('bogus', @pass) }
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

  test "attempting to set the password for an invalid user raises an error" do
    @kadm5 = Krb5Auth::Kadm5.new(@user, @pass)
    assert_raise(Krb5Auth::Kadm5::Exception){ @kadm5.set_password('bogususer', 'xxxyyy') }
  end

  test "create_principal basic functionality" do
    @kadm = Krb5Auth::Kadm5.new(@user, @pass)
    assert_respond_to(@kadm, :create_principal)
  end

  test "create_principal creates a user as expected" do
    assert_nothing_raised{ @kadm = Krb5Auth::Kadm5.new(@user, @pass) }
    assert_nothing_raised{ @kadm.create_principal(@test_princ, "changeme") }
  end

  test "create_principal requires two arguments" do
    assert_nothing_raised{ @kadm = Krb5Auth::Kadm5.new(@user, @pass) }
    assert_raise(ArgumentError){ @kadm.create_principal }
    assert_raise(ArgumentError){ @kadm.create_principal(@user) }
    assert_raise(ArgumentError){ @kadm.create_principal(@user, @pass, @pass) }
  end

  test "attempting to create a principal that already exists raises an error" do
    assert_nothing_raised{ @kadm = Krb5Auth::Kadm5.new(@user, @pass) }
    assert_nothing_raised{ @kadm.create_principal(@test_princ, "changeme") }
    assert_raise(Krb5Auth::Kadm5::Exception){ @kadm.create_principal(@test_princ, "changeme") }
  end

  test "delete_principal basic functionality" do
    assert_nothing_raised{ @kadm = Krb5Auth::Kadm5.new(@user, @pass) }
    assert_respond_to(@kadm, :delete_principal)
  end

  test "delete_principal works as expected" do
    assert_nothing_raised{ @kadm = Krb5Auth::Kadm5.new(@user, @pass) }
    assert_nothing_raised{ @kadm.create_principal(@test_princ, "changeme") }
    assert_nothing_raised{ @kadm.delete_principal(@test_princ) }
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

  test "get_principal returns a Struct::Principal object if found" do
    assert_nothing_raised{ @kadm = Krb5Auth::Kadm5.new(@user, @pass) }
    assert_nothing_raised{ @kadm.create_principal(@test_princ, "changeme") }
    assert_nothing_raised{ @struct = @kadm.get_principal(@test_princ) }
    assert_kind_of(Struct::Principal, @struct)
  end

  test "get_principal raises an error if not found" do
    @kadm = Krb5Auth::Kadm5.new(@user, @pass)
    assert_raise(Krb5Auth::Kadm5::Exception){ @kadm.get_principal('bogus') }
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

  test "close basic functionality" do
    @kadm = Krb5Auth::Kadm5.new(@user, @pass)
    assert_respond_to(@kadm, :close)
    assert_nothing_raised{ @kadm.close }
  end

  test "calling close multiple times is a no-op" do
    @kadm = Krb5Auth::Kadm5.new(@user, @pass)
    assert_nothing_raised{ @kadm.close }
    assert_nothing_raised{ @kadm.close }
    assert_nothing_raised{ @kadm.close }
  end

  test "close does not accept any arguments" do
    @kadm = Krb5Auth::Kadm5.new(@user, @pass)
    assert_raise(ArgumentError){ @kadm.close(1) }
  end

  test "calling close on an already closed object raises an error" do
    @kadm = Krb5Auth::Kadm5.new(@user, @pass)
    @kadm.create_principal(@test_princ, "changeme")
    @kadm.close

    assert_raise(Krb5Auth::Kadm5::Exception){ @kadm.get_principal(@test_princ) }
    assert_raise_message('no context has been established'){ @kadm.get_principal(@test_princ) }
  end

  def teardown
    if @kadm
      @kadm.delete_principal(@test_princ) rescue nil
      @kadm.close
    end
    @user   = nil
    @pass   = nil
    @kadm   = nil
    @struct = nil
  end

  def self.shutdown
    @@info = nil
  end
end
