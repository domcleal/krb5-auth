########################################################################
# test_config.rb
#
# Test suite for the Krb5Auth::Kadm5::Config class.
########################################################################
require 'rubygems'
gem 'test-unit'

require 'test/unit'
require 'krb5_auth'

class TC_Kadm5_Config < Test::Unit::TestCase
  def setup
    @config = Krb5Auth::Kadm5::Config.new
  end

  test "realm basic functionality" do
    assert_respond_to(@config, :realm)
    assert_kind_of(String, @config.realm)
  end

  test "kadmind_port basic functionality" do
    assert_respond_to(@config, :kadmind_port)
    assert_kind_of(Fixnum, @config.kadmind_port)
  end

  test "kpasswd_port basic functionality" do
    assert_respond_to(@config, :kpasswd_port)
    assert_kind_of(Fixnum, @config.kpasswd_port)
  end

  test "admin_server basic functionality" do
    assert_respond_to(@config, :admin_server)
    assert_kind_of(String, @config.admin_server)
  end

  test "admin_keytab basic functionality" do
    assert_respond_to(@config, :admin_keytab)
    assert_kind_of(String, @config.admin_keytab)
  end

  test "acl_file basic functionality" do
    assert_respond_to(@config, :acl_file)
    assert_kind_of(String, @config.acl_file)
  end

  test "dict_file basic functionality" do
    assert_respond_to(@config, :dict_file)
    assert_kind_of([String, NilClass], @config.dict_file)
  end

  test "stash_file basic functionality" do
    assert_respond_to(@config, :stash_file)
    assert_kind_of([String, NilClass], @config.stash_file)
  end

  def teardown
    @config = nil
  end
end
