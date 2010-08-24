#include "krb5_auth.h"

extern VALUE mKerberos;
extern VALUE cKrb5;
extern VALUE cKrb5CCache;
extern VALUE cKrb5Context;
extern VALUE cKrb5Keytab;
extern VALUE cKrb5KtEntry;
extern VALUE cKrb5Exception;
extern VALUE cKrb5Principal;
extern VALUE cKadm5;
extern VALUE cKadm5Config;
extern VALUE cKadm5Exception;
extern VALUE cKadm5Policy;

// Free function for the Krb5Auth::Krb5 class.
static void rkrb5_free(RUBY_KRB5* ptr){
  if(!ptr)
    return;

  if(ptr->keytab)
    krb5_kt_close(ptr->ctx, ptr->keytab);

  if(ptr->ctx)
    krb5_free_cred_contents(ptr->ctx, &ptr->creds);

  if(ptr->princ)
    krb5_free_principal(ptr->ctx, ptr->princ);

  if(ptr->ctx)
    krb5_free_context(ptr->ctx);

  free(ptr);
}

// Allocation function for the Krb5Auth::Krb5 class.
static VALUE rkrb5_allocate(VALUE klass){
  RUBY_KRB5* ptr = malloc(sizeof(RUBY_KRB5));
  memset(ptr, 0, sizeof(RUBY_KRB5));
  return Data_Wrap_Struct(klass, 0, rkrb5_free, ptr);
}

/*
 * call-seq:
 *   Krb5Auth::Krb5.new
 *
 * Creates and returns a new Krb5Auth::Krb5 object. This initializes the
 * context for future method calls on that object.
 */
static VALUE rkrb5_initialize(VALUE self){
  RUBY_KRB5* ptr;
  krb5_error_code kerror;

  Data_Get_Struct(self, RUBY_KRB5, ptr); 

  kerror = krb5_init_context(&ptr->ctx); 

  if(kerror)
    rb_raise(cKrb5Exception, "krb5_init_context: %s", error_message(kerror));

  return self;
}

/*
 * call-seq:
 *   krb.get_default_realm # => 'YOUR.REALM.COM'
 *
 * Returns the default Kerberos realm on your system.
 */
static VALUE rkrb5_get_default_realm(VALUE self){
  RUBY_KRB5* ptr;
  char* realm;
  krb5_error_code kerror;

  Data_Get_Struct(self, RUBY_KRB5, ptr); 

  kerror = krb5_get_default_realm(ptr->ctx, &realm);

  if(kerror)
    rb_raise(cKrb5Exception, "krb5_get_default_realm: %s", error_message(kerror));

  return rb_str_new2(realm);
}

/*
 * call-seq:
 *   krb.set_default_realm(realm = nil)
 *
 * Sets the default realm to +realm+. If no argument is provided, then the
 * default realm in your krb5.conf file is used.
 */
static VALUE rkrb5_set_default_realm(int argc, VALUE* argv, VALUE self){
  RUBY_KRB5* ptr;
  VALUE v_realm;
  char* realm;
  krb5_error_code kerror;

  Data_Get_Struct(self, RUBY_KRB5, ptr); 

  rb_scan_args(argc, argv, "01", &v_realm); 

  if(NIL_P(v_realm)){
    realm = NULL;
  }
  else{
    Check_Type(v_realm, T_STRING);
    realm = StringValuePtr(v_realm);
  }

  kerror = krb5_set_default_realm(ptr->ctx, realm);

  if(kerror)
    rb_raise(cKrb5Exception, "krb5_set_default_realm: %s", error_message(kerror));

  return self;
}

/* call-seq:
 *   krb5.get_init_creds_keytab(principal = nil, keytab = nil, service = nil)
 *
 * Acquire credentials for +principal+ from +keytab+ using +service+. If
 * no principal is specified, then a principal is derived from the service
 * name. If no service name is specified, kerberos defaults to "host".
 *
 * If no keytab file is provided, the default keytab file is used. This is
 * typically /etc/krb5.keytab.
 */
static VALUE rkrb5_get_init_creds_keytab(int argc, VALUE* argv, VALUE self){
  RUBY_KRB5* ptr;
  VALUE v_user, v_keytab_name, v_service;
  char* user;
  char* service;
  char keytab_name[MAX_KEYTAB_NAME_LEN];

  krb5_error_code kerror;
  krb5_get_init_creds_opt opt;
  krb5_creds cred;

  Data_Get_Struct(self, RUBY_KRB5, ptr); 

  if(!ptr->ctx)
    rb_raise(cKrb5Exception, "no context has been established");

  rb_scan_args(argc, argv, "03", &v_user, &v_keytab_name, &v_service);

  // We need the service information for later.
  if(NIL_P(v_service)){
    service = NULL;
  }
  else{
    Check_Type(v_service, T_STRING);
    service = StringValuePtr(v_service);
  }

  // Convert the name (or service name) to a kerberos principal.
  if(NIL_P(v_user)){
    kerror = krb5_sname_to_principal(
      ptr->ctx,
      NULL,
      service,
      KRB5_NT_SRV_HST,
      &ptr->princ
    );

    if(kerror)
      rb_raise(cKrb5Exception, "krb5_sname_to_principal: %s", error_message(kerror));
  }
  else{
    Check_Type(v_user, T_STRING);
    user = StringValuePtr(v_user);

    kerror = krb5_parse_name(ptr->ctx, user, &ptr->princ); 

    if(kerror)
      rb_raise(cKrb5Exception, "krb5_parse_name: %s", error_message(kerror));
  }

  // Use the default keytab if none is specified.
  if(NIL_P(v_keytab_name)){
    kerror = krb5_kt_default_name(ptr->ctx, keytab_name, MAX_KEYTAB_NAME_LEN);

    if(kerror)
      rb_raise(cKrb5Exception, "krb5_kt_default_name: %s", error_message(kerror));
  }
  else{
    Check_Type(v_keytab_name, T_STRING);
    strncpy(keytab_name, StringValuePtr(v_keytab_name), MAX_KEYTAB_NAME_LEN);
  }

  kerror = krb5_kt_resolve(
    ptr->ctx,
    keytab_name,
    &ptr->keytab
  );

  if(kerror)
    rb_raise(cKrb5Exception, "krb5_kt_resolve: %s", error_message(kerror));

  krb5_get_init_creds_opt_init(&opt);

  kerror = krb5_get_init_creds_keytab(
    ptr->ctx,
    &cred,
    ptr->princ,
    ptr->keytab,
    0,
    service,
    &opt
  );

  if(kerror)
    rb_raise(cKrb5Exception, "krb5_get_init_creds_keytab: %s", error_message(kerror));

  return self; 
}

/* call-seq:
 *   krb5.change_password(old, new)
 *
 * Changes the password for the principal from +old+ to +new+. The principal
 * is defined as whoever the last principal was authenticated via the
 * Krb5#get_init_creds_password method.
 *
 * Attempting to change a password before a principal has been established
 * will raise an error.
 *
 * Example:
 *
 * krb5.get_init_creds_password('foo', 'XXXXXX') # Authenticate 'foo' user
 * krb5.change_password('XXXXXX', 'YYYYYY')      # Change password for 'foo'
 */
static VALUE rkrb5_change_password(VALUE self, VALUE v_old, VALUE v_new){
  Check_Type(v_old, T_STRING);
  Check_Type(v_new, T_STRING);

  RUBY_KRB5* ptr;
  krb5_data result_string;
  krb5_data pw_result_string;
  krb5_error_code kerror;

  int pw_result;
  char* old_passwd = StringValuePtr(v_old);
  char* new_passwd = StringValuePtr(v_new);

  Data_Get_Struct(self, RUBY_KRB5, ptr); 

  if(!ptr->ctx)
    rb_raise(cKrb5Exception, "no context has been established"); 

  if(!ptr->princ)
    rb_raise(cKrb5Exception, "no principal has been established"); 

  kerror = krb5_get_init_creds_password(
    ptr->ctx,
    &ptr->creds,
    ptr->princ,
    old_passwd,
    NULL,
    NULL,
    0,
    "kadmin/changepw",
    NULL
  );

  if(kerror)
    rb_raise(cKrb5Exception, "krb5_get_init_creds_password: %s", error_message(kerror));

  kerror = krb5_change_password(
    ptr->ctx,
    &ptr->creds,
    new_passwd,
    &pw_result,
    &pw_result_string,
    &result_string
  );

  if(kerror)
    rb_raise(cKrb5Exception, "krb5_change_password: %s", error_message(kerror));

  return Qtrue;
}

/*
 * call-seq:
 *   krb5.get_init_creds_password(user, password)
 *
 * Authenticates the credentials of +user+ using +password+, and has the effect
 * of setting the principal and context internally. This method must typically
 * be called before using other methods.
 */
static VALUE rkrb5_get_init_creds_passwd(VALUE self, VALUE v_user, VALUE v_pass){
  Check_Type(v_user, T_STRING);
  Check_Type(v_pass, T_STRING);

  RUBY_KRB5* ptr;
  char* user = StringValuePtr(v_user);
  char* pass = StringValuePtr(v_pass);
  krb5_error_code kerror;

  Data_Get_Struct(self, RUBY_KRB5, ptr); 

  if(!ptr->ctx)
    rb_raise(cKrb5Exception, "no context has been established");

  kerror = krb5_parse_name(ptr->ctx, user, &ptr->princ); 

  if(kerror)
    rb_raise(cKrb5Exception, "krb5_parse_name: %s", error_message(kerror));

  kerror = krb5_get_init_creds_password(
    ptr->ctx,
    &ptr->creds,
    ptr->princ,
    pass,
    0,
    NULL,
    0,
    NULL,
    NULL
  );

  if(kerror)
    rb_raise(cKrb5Exception, "krb5_get_init_creds_password: %s", error_message(kerror));

  return Qtrue;
}

/* 
 * call-seq:
 *   krb5.close
 *
 * Handles cleanup of the Krb5 object, freeing any credentials, principal or
 * context associated with the object.
 */
static VALUE rkrb5_close(VALUE self){
  RUBY_KRB5* ptr;

  Data_Get_Struct(self, RUBY_KRB5, ptr);

  if(ptr->ctx)
    krb5_free_cred_contents(ptr->ctx, &ptr->creds);

  if(ptr->princ)
    krb5_free_principal(ptr->ctx, ptr->princ);

  if(ptr->ctx)
    krb5_free_context(ptr->ctx);

  ptr->ctx = NULL;
  ptr->princ = NULL;

  return Qtrue;
}

/*
 * call-seq:
 *   krb5.get_default_principal
 *
 * Returns the default principal for the current realm based on the current
 * credentials cache.
 *
 * If no credentials cache is found then an error is raised.
 */
static VALUE rkrb5_get_default_principal(VALUE self){
  char* princ_name;
  RUBY_KRB5* ptr;
  krb5_ccache ccache;  
  krb5_error_code kerror;

  Data_Get_Struct(self, RUBY_KRB5, ptr); 

  if(!ptr->ctx)
    rb_raise(cKrb5Exception, "no context has been established");

  // Get the default credentials cache
  kerror = krb5_cc_default(ptr->ctx, &ccache);

  if(kerror)
    rb_raise(cKrb5Exception, "krb5_cc_default: %s", error_message(kerror));

  kerror = krb5_cc_get_principal(ptr->ctx, ccache, &ptr->princ);

  if(kerror){
    krb5_cc_close(ptr->ctx, ccache);
    rb_raise(cKrb5Exception, "krb5_cc_get_principal: %s", error_message(kerror));
  }

  krb5_cc_close(ptr->ctx, ccache);

  kerror = krb5_unparse_name(ptr->ctx, ptr->princ, &princ_name);

  if(kerror)
    rb_raise(cKrb5Exception, "krb5_cc_default: %s", error_message(kerror));

  return rb_str_new2(princ_name);
}

void Init_krb5_auth(){
  mKerberos      = rb_define_module("Krb5Auth");
  cKrb5          = rb_define_class_under(mKerberos, "Krb5", rb_cObject);
  cKrb5Exception = rb_define_class_under(cKrb5, "Exception", rb_eStandardError);

  // Allocation functions
  rb_define_alloc_func(cKrb5, rkrb5_allocate);
  
  // Initializers
  rb_define_method(cKrb5, "initialize", rkrb5_initialize, 0);
  
  // Krb5 Methods
  rb_define_method(cKrb5, "change_password", rkrb5_change_password, 2);
  rb_define_method(cKrb5, "close", rkrb5_close, 0);
  rb_define_method(cKrb5, "get_default_realm", rkrb5_get_default_realm, 0);
  rb_define_method(cKrb5, "get_init_creds_password", rkrb5_get_init_creds_passwd, 2);
  rb_define_method(cKrb5, "get_init_creds_keytab", rkrb5_get_init_creds_keytab, -1);
  rb_define_method(cKrb5, "get_default_principal", rkrb5_get_default_principal, 0);
  rb_define_method(cKrb5, "set_default_realm", rkrb5_set_default_realm, -1);

  rb_define_alias(cKrb5, "default_realm", "get_default_realm");
  rb_define_alias(cKrb5, "default_principal", "get_default_principal");

  /* 0.9.0: The version of the custom krb5_auth library */
  rb_define_const(cKrb5, "VERSION", rb_str_new2("0.9.0"));

  /* 0x0000: None */
  rb_define_const(cKrb5, "ENCTYPE_NULL", INT2FIX(ENCTYPE_NULL));

  /* 0x0001: DES cbc mode with CRC-32 */
  rb_define_const(cKrb5, "ENCTYPE_DES_CBC_CRC", INT2FIX(ENCTYPE_DES_CBC_CRC));

  /* 0x0002: DES cbc mode with RSA-MD4 */
  rb_define_const(cKrb5, "ENCTYPE_DES_CBC_MD4", INT2FIX(ENCTYPE_DES_CBC_MD4));

  /* 0x0003: DES cbc mode with RSA-MD5 */
  rb_define_const(cKrb5, "ENCTYPE_DES_CBC_MD5", INT2FIX(ENCTYPE_DES_CBC_MD5));

  /* 0x0004: DES cbc mode raw */
  rb_define_const(cKrb5, "ENCTYPE_DES_CBC_RAW", INT2FIX(ENCTYPE_DES_CBC_RAW));

  /* 0x0005: DES-3 cbc mode with NIST-SHA */
  rb_define_const(cKrb5, "ENCTYPE_DES3_CBC_SHA", INT2FIX(ENCTYPE_DES3_CBC_SHA));

  /* 0x0006: DES-3 cbc mode raw */
  rb_define_const(cKrb5, "ENCTYPE_DES3_CBC_RAW", INT2FIX(ENCTYPE_DES3_CBC_RAW));

  /* 0x0008: HMAC SHA1 */
  rb_define_const(cKrb5, "ENCTYPE_DES_HMAC_SHA1", INT2FIX(ENCTYPE_DES_HMAC_SHA1));

  /* 0x0009: DSA with SHA1, CMS signature */
  rb_define_const(cKrb5, "ENCTYPE_DSA_SHA1_CMS", INT2FIX(ENCTYPE_DSA_SHA1_CMS));

  /* 0x000a: MD5 with RSA, CMS signature */
  rb_define_const(cKrb5, "ENCTYPE_MD5_RSA_CMS", INT2FIX(ENCTYPE_MD5_RSA_CMS));

  /* 0x000b: SHA1 with RSA, CMS signature */
  rb_define_const(cKrb5, "ENCTYPE_SHA1_RSA_CMS", INT2FIX(ENCTYPE_SHA1_RSA_CMS));

  /* 0x000c: RC2 cbc mode, CMS enveloped data */
  rb_define_const(cKrb5, "ENCTYPE_RC2_CBC_ENV", INT2FIX(ENCTYPE_RC2_CBC_ENV));

  /* 0x000d: RSA encryption, CMS enveloped data */
  rb_define_const(cKrb5, "ENCTYPE_RSA_ENV", INT2FIX(ENCTYPE_RSA_ENV));

  /* 0x000e: RSA w/OEAP encryption, CMS enveloped data */
  rb_define_const(cKrb5, "ENCTYPE_RSA_ES_OAEP_ENV", INT2FIX(ENCTYPE_RSA_ES_OAEP_ENV));

  /* 0x000f: DES-3 cbc mode, CMS enveloped data */
  rb_define_const(cKrb5, "ENCTYPE_DES3_CBC_ENV", INT2FIX(ENCTYPE_DES3_CBC_ENV));

  /* 0x0010: DES3 CBC SHA1 */
  rb_define_const(cKrb5, "ENCTYPE_DES3_CBC_SHA1", INT2FIX(ENCTYPE_DES3_CBC_SHA1));

  /* 0x0011: AES128 CTS HMAC SHA1 96 */
  rb_define_const(cKrb5, "ENCTYPE_AES128_CTS_HMAC_SHA1_96", INT2FIX(ENCTYPE_AES128_CTS_HMAC_SHA1_96));

  /* 0x0012: AES256 CTS HMAC SHA1 96 */
  rb_define_const(cKrb5, "ENCTYPE_AES256_CTS_HMAC_SHA1_96", INT2FIX(ENCTYPE_AES256_CTS_HMAC_SHA1_96));

  /* 0x0017: ARCFOUR HMAC */
  rb_define_const(cKrb5, "ENCTYPE_ARCFOUR_HMAC", INT2FIX(ENCTYPE_ARCFOUR_HMAC));

  /* 0x0018: ARCFOUR HMAC EXP */
  rb_define_const(cKrb5, "ENCTYPE_ARCFOUR_HMAC_EXP", INT2FIX(ENCTYPE_ARCFOUR_HMAC_EXP));

  /* 0x01ff: Unknown */
  rb_define_const(cKrb5, "ENCTYPE_UNKNOWN", INT2FIX(ENCTYPE_UNKNOWN));

  // Class initialization

  Init_context();
  Init_ccache();
  Init_kadm5();
  Init_config();
  Init_policy();
  Init_principal();
  Init_keytab();
  Init_keytab_entry();
}
