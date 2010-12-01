########################################################################
# test_krb5_keytab.rb
#
# Test suite for the Krb5Auth::Krb5::Keytab class.
#
# At the moment this test suite assumes that there are two or more
# principals in the keytab. Temporary keytab creation needs to be
# handled in the startup method somehow.
########################################################################
require 'rubygems'
gem 'test-unit'

require 'tmpdir'
require 'fileutils'
require 'open3'
require 'test/unit'
require 'krb5_auth'

class TC_Krb5_Keytab < Test::Unit::TestCase
  def self.startup
    @@file = Krb5Auth::Krb5::Keytab.new.default_name.split(':').last

    unless File.exists?(@@file)
      temp = Dir.tmpdir + "/test.keytab"
      @@file = "FILE:" + temp
      FileUtils.touch(temp)
    end

    @@home_dir = ENV['HOME'] || ENV['USER_PROFILE']
  end

  def setup
    @keytab = Krb5Auth::Krb5::Keytab.new
    @realm  = Krb5Auth::Kadm5::Config.new.realm
    @entry  = nil
    @name   = nil
  end

  test "constructor takes an optional name" do
    assert_nothing_raised{ @keytab = Krb5Auth::Krb5::Keytab.new("FILE:/usr/local/var/keytab") }
    assert_nothing_raised{ @keytab = Krb5Auth::Krb5::Keytab.new("FILE:/bogus/keytab") }
  end

  test "using an invalid residual type causes an error" do
    omit("Invalid residual type test skipped for now")
    assert_raise(Krb5Auth::Krb5::Keytab::Exception){
      @keytab = Krb5Auth::Krb5::Keytab.new("BOGUS:/bogus/keytab")
    }
  end

  test "keytab name passed to constructor must be a string" do
    assert_raise(TypeError){ Krb5Auth::Krb5::Keytab.new(1) }
  end

  test "name basic functionality" do
    assert_respond_to(@keytab, :name)
    assert_kind_of(String, @keytab.name)
  end

  test "name is set to default name if no argument is passed to constructor" do
    assert_equal(@keytab.name, @keytab.default_name)
  end

  test "name is set to value passed to constructor" do
    temp = "FILE:" + Dir.tmpdir + "/test.keytab"
    @keytab = Krb5Auth::Krb5::Keytab.new(temp)
    assert_equal(@keytab.name, temp)
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
    assert_nothing_raised{ @keytab = Krb5Auth::Krb5::Keytab.new(@@file) }
    assert_respond_to(@keytab, :each)
    assert_nothing_raised{ @keytab.each{} }
  end

  test "each method yields a keytab entry object" do
    array = []
    assert_nothing_raised{ @keytab = Krb5Auth::Krb5::Keytab.new(@@file) }
    assert_nothing_raised{ @keytab.each{ |entry| array << entry } }
    assert_kind_of(Krb5Auth::Krb5::Keytab::Entry, array[0])
    assert_true(array.size >= 1)
  end

  test "get_entry basic functionality" do
    assert_respond_to(@keytab, :get_entry)
  end

  test "get_entry returns an entry if found in the keytab" do
    @user = "testuser1@" + @realm
    assert_nothing_raised{ @keytab = Krb5Auth::Krb5::Keytab.new(@@file) }
    assert_nothing_raised{ @entry = @keytab.get_entry(@user) }
    assert_kind_of(Krb5Auth::Krb5::Keytab::Entry, @entry)
  end

  test "get_entry raises an error if no entry is found" do
    @user = "bogus_user@" + @realm
    assert_nothing_raised{ @keytab = Krb5Auth::Krb5::Keytab.new(@@file) }
    assert_raise(Krb5Auth::Krb5::Exception){ @keytab.get_entry(@user) }
  end

  test "find is an alias for get_entry" do
    assert_respond_to(@keytab, :find)
    assert_alias_method(@keytab, :find, :get_entry)
  end

=begin
  test "add_entry basic functionality" do
    assert_respond_to(@keytab, :add_entry)
  end

  test "add_entry can add a valid principal" do
    @user = "testuser1@" + @realm
    assert_nothing_raised{ @keytab = Krb5Auth::Krb5::Keytab.new(@@file) }
    assert_nothing_raised{ @keytab.add_entry(@user) }
  end

  test "add_entry fails if an invalid user is added" do
    @user = "bogus_user@" + @realm
    assert_nothing_raised{ @keytab = Krb5Auth::Krb5::Keytab.new(@@file) }
    assert_raise(Krb5Auth::Krb5::Exception){ @keytab.add_entry(@user) }
  end
=end

  test "foreach singleton method basic functionality" do
    assert_respond_to(Krb5Auth::Krb5::Keytab, :foreach)
    assert_nothing_raised{ Krb5Auth::Krb5::Keytab.foreach(@@file){} }
  end

  test "foreach singleton method yields keytab entry objects" do
    array = []
    assert_nothing_raised{ Krb5Auth::Krb5::Keytab.foreach(@@file){ |entry| array << entry } }
    assert_kind_of(Krb5Auth::Krb5::Keytab::Entry, array[0])
    assert_true(array.size >= 1)
  end

  def teardown
    @keytab.close if @keytab
    @keytab = nil
    @entry  = nil
    @realm  = nil
  end
end
