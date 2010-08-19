#include "krb5_auth.h"

// Free function for the Krb5Auth::Krb5::Keytab class.
static void rkrb5_princ_free(RUBY_KRB5_PRINC* ptr){
  if(!ptr)
    return;

  free(ptr);
}

// Allocation function for the Krb5Auth::Krb5::Keytab class.
static VALUE rkrb5_princ_allocate(VALUE klass){
  RUBY_KRB5_PRINC* ptr = malloc(sizeof(RUBY_KRB5_PRINC));
  memset(ptr, 0, sizeof(RUBY_KRB5_PRINC));
  return Data_Wrap_Struct(klass, 0, rkrb5_princ_free, ptr);
}

/*
 * call-seq:
 *   Krb5Auth::Krb5::Principal.new(name)
 *
 * Creates and returns a new Krb5::Principal object. If a block is provided
 * then it yields itself.
 *
 * Example:
 *
 *   principal1 = Krb5Auth::Krb5::Principal.new('Jon')
 *
 *   principal2 = Krb5Auth::Krb5::Principal.new('Jon') do |pr|
 *     pr.expire_time = Time.now + 20000
 *   end
 */
static VALUE rkrb5_princ_initialize(VALUE self, VALUE v_name){
  RUBY_KRB5_PRINC* ptr;
  krb5_error_code kerror;

  Data_Get_Struct(self, RUBY_KRB5_PRINC, ptr); 

  kerror = krb5_init_context(&ptr->ctx);

  if(kerror)
    rb_raise(cKrb5Exception, "krb5_init_context failed: %s", error_message(kerror));

  if(!NIL_P(v_name)){
    char* name;
    Check_Type(v_name, T_STRING);
    name = StringValuePtr(v_name);
    kerror = krb5_parse_name(ptr->ctx, name, &ptr->principal);

    if(kerror)
      rb_raise(cKrb5Exception, "krb5_parse_name failed: %s", error_message(kerror));

    rb_iv_set(self, "@name", v_name);
  }

  if(rb_block_given_p())
    rb_yield(self);

  return self;
}

/*
 * call-seq:
 *   principal.realm
 *
 * Returns the realm for the given principal.
 */
static VALUE rkrb5_princ_get_realm(VALUE self){
  RUBY_KRB5_PRINC* ptr;
  Data_Get_Struct(self, RUBY_KRB5_PRINC, ptr); 

  return rb_str_new2(krb5_princ_realm(ptr->ctx, ptr->principal)->data);
}

/*
 * call-seq:
 *   principal.realm = 'YOUR.REALM'
 *
 * Sets the realm for the given principal.
 */
static VALUE rkrb5_princ_set_realm(VALUE self, VALUE v_realm){
  RUBY_KRB5_PRINC* ptr;
  Data_Get_Struct(self, RUBY_KRB5_PRINC, ptr); 
  krb5_data kdata;

  Check_Type(v_realm, T_STRING);
  kdata.data = StringValuePtr(v_realm);

  krb5_princ_set_realm(ptr->ctx, ptr->principal, &kdata);

  return v_realm;
}

/*
 * call-seq:
 *   principal1 == principal2
 *
 * Returns whether or not two principals are the same.
 */
static VALUE rkrb5_princ_equal(VALUE self, VALUE v_other){
  RUBY_KRB5_PRINC* ptr1;
  RUBY_KRB5_PRINC* ptr2;
  VALUE v_bool = Qfalse;

  Data_Get_Struct(self, RUBY_KRB5_PRINC, ptr1); 
  Data_Get_Struct(v_other, RUBY_KRB5_PRINC, ptr2); 

  if(krb5_principal_compare(ptr1->ctx, ptr1->principal, ptr2->principal))
    v_bool = Qtrue;

  return v_bool;
}

void Init_principal(){
  /* The Krb5Auth::Krb5::Principal class encapsulates a Kerberos principal. */
  cKrb5Principal = rb_define_class_under(cKrb5, "Principal", rb_cObject);

  // Allocation Function
  rb_define_alloc_func(cKrb5Principal, rkrb5_princ_allocate);

  // Constructor
  rb_define_method(cKrb5Principal, "initialize", rkrb5_princ_initialize, 1);

  // Instance Methods
  rb_define_method(cKrb5Principal, "realm", rkrb5_princ_get_realm, 0);
  rb_define_method(cKrb5Principal, "realm=", rkrb5_princ_set_realm, 1);
  rb_define_method(cKrb5Principal, "==", rkrb5_princ_equal, 1);

  // Attributes
  rb_define_attr(cKrb5Principal, "name", 1, 0);
  rb_define_attr(cKrb5Principal, "expire_time", 1, 1);
  rb_define_attr(cKrb5Principal, "last_password_change", 1, 1);
  rb_define_attr(cKrb5Principal, "password_expiration", 1, 1);
  rb_define_attr(cKrb5Principal, "max_life", 1, 1);
  rb_define_attr(cKrb5Principal, "mod_name", 1, 1);
  rb_define_attr(cKrb5Principal, "mod_date", 1, 1);
  rb_define_attr(cKrb5Principal, "attributes", 1, 1);
  rb_define_attr(cKrb5Principal, "vno", 1, 1);
  rb_define_attr(cKrb5Principal, "policy", 1, 1);
  rb_define_attr(cKrb5Principal, "max_renewable_life", 1, 1);
  rb_define_attr(cKrb5Principal, "last_success", 1, 1);
  rb_define_attr(cKrb5Principal, "last_failed", 1, 1);
  rb_define_attr(cKrb5Principal, "fail_auth_count", 1, 1);
}
