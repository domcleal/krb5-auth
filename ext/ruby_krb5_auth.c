#include <ruby.h>
#include <krb5.h>
#include <string.h>

#ifdef HAVE_KADM5_ADMIN_H
#include <kadm5/admin.h>
#endif

VALUE cKrb5Exception;
VALUE cKadm5Exception;
VALUE sPrincipalStruct;

typedef struct {
  krb5_context ctx;
  krb5_creds creds;
  krb5_principal princ;
} RUBY_KRB5;

typedef struct {
  krb5_context ctx;
  krb5_principal princ;
  void* handle;
} RUBY_KADM5;

static void rkrb5_free(RUBY_KRB5* ptr){
  if(!ptr)
    return;

  if(ptr->ctx)
    krb5_free_cred_contents(ptr->ctx, &ptr->creds);

  if(ptr->princ)
    krb5_free_principal(ptr->ctx, ptr->princ);

  if(ptr->ctx)
    krb5_free_context(ptr->ctx);

  free(ptr);
}

static void rkadm5_free(RUBY_KADM5* ptr){
  if(!ptr)
    return;

  if(ptr->princ)
    krb5_free_principal(ptr->ctx, ptr->princ);

  if(ptr->ctx)
    krb5_free_context(ptr->ctx);

  free(ptr);
}

static VALUE rkrb5_allocate(VALUE klass){
  RUBY_KRB5* ptr = malloc(sizeof(RUBY_KRB5));
  memset(ptr, 0, sizeof(RUBY_KRB5));
  return Data_Wrap_Struct(klass, 0, rkrb5_free, ptr);
}

static VALUE rkadm5_allocate(VALUE klass){
  RUBY_KADM5* ptr = malloc(sizeof(RUBY_KADM5));
  memset(ptr, 0, sizeof(RUBY_KADM5));
  return Data_Wrap_Struct(klass, 0, rkadm5_free, ptr);
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
  Data_Get_Struct(self, RUBY_KRB5, ptr); 
  krb5_error_code kerror;

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

#ifdef HAVE_KADM5_ADMIN_H

/*
 * call-seq:
 *   Krb5Auth::Kadm5.new(admin_user, admin_password)
 *
 * Creates and returns a new Krb5Auth::Kadm5 object. The +admin_user+ and
 * +admin_password+ arguments are an administrative account that must be
 * authenticated before any other admin methods can be used.
 */
static VALUE rkadm5_initialize(VALUE self, VALUE v_user, VALUE v_pass){
  RUBY_KADM5* ptr;
  char* user;
  char* pass;
  krb5_error_code kerror;

  Data_Get_Struct(self, RUBY_KADM5, ptr);

  Check_Type(v_user, T_STRING);
  Check_Type(v_pass, T_STRING);

  user = StringValuePtr(v_user);
  pass = StringValuePtr(v_pass);

  kerror = krb5_init_context(&ptr->ctx);

  if(kerror)
    rb_raise(cKadm5Exception, "krb5_init_context: %s", error_message(kerror));

#ifdef KADM5_API_VERSION_3
  kerror = kadm5_init_with_password(
    ptr->ctx,
    user,
    pass,
    KADM5_ADMIN_SERVICE,
    NULL,
    KADM5_STRUCT_VERSION,
    KADM5_API_VERSION_3,
    NULL,
    &ptr->handle
  );
#else
  kerror = kadm5_init_with_password(
    user,
    pass,
    KADM5_ADMIN_SERVICE,
    NULL,
    KADM5_STRUCT_VERSION,
    KADM5_API_VERSION_2,
    NULL,
    &ptr->handle
  );
#endif

  if(kerror)
    rb_raise(cKadm5Exception, "kadm5_init_with_password: %s", error_message(kerror));

  return self;
}

/* call-seq:
 *   kadm5.set_password(user, password)
 *
 * Set the password for +user+ (i.e. the principal) to +password+.
 */
static VALUE rkadm5_set_password(VALUE self, VALUE v_user, VALUE v_pass){
  Check_Type(v_user, T_STRING);
  Check_Type(v_pass, T_STRING);

  RUBY_KADM5* ptr;
  char* user = StringValuePtr(v_user);
  char* pass = StringValuePtr(v_pass);
  krb5_error_code kerror;

  Data_Get_Struct(self, RUBY_KADM5, ptr);

  if(!ptr->ctx)
    rb_raise(cKadm5Exception, "no context has been established");

  kerror = krb5_parse_name(ptr->ctx, user, &ptr->princ); 

  if(kerror)
    rb_raise(cKadm5Exception, "krb5_parse_name: %s", error_message(kerror));

  kerror = kadm5_chpass_principal(ptr->handle, ptr->princ, pass);

  if(kerror)
    rb_raise(cKadm5Exception, "kadm5_chpass_principal: %s", error_message(kerror));

  return self;
}

/*
 * call-seq:
 *   kadm5.create_principal(name, password)
 *
 * Creates a new principal +name+ with an initial password of +password+.
 */
static VALUE rkadm5_create_principal(VALUE self, VALUE v_user, VALUE v_pass){
  RUBY_KADM5* ptr;
  char* user;
  char* pass;
  int mask;
  kadm5_principal_ent_rec princ;
  krb5_error_code kerror;

  Data_Get_Struct(self, RUBY_KADM5, ptr);

  Check_Type(v_user, T_STRING);
  Check_Type(v_pass, T_STRING);

  memset(&princ, 0, sizeof(princ));

  mask = KADM5_PRINCIPAL;
  user = StringValuePtr(v_user);
  pass = StringValuePtr(v_pass);

  if(!ptr->ctx)
    rb_raise(cKadm5Exception, "no context has been established");

  kerror = krb5_parse_name(ptr->ctx, user, &princ.principal);

  if(kerror)
    rb_raise(cKadm5Exception, "krb5_parse_name: %s", error_message(kerror));

  kerror = kadm5_create_principal(ptr->handle, &princ, mask, pass); 

  if(kerror)
    rb_raise(cKadm5Exception, "kadm5_create_principal: %s", error_message(kerror));

  krb5_free_principal(ptr->ctx, princ.principal);

  return self;
}

/* call-seq:
 *   kadm5.delete_principal(name)
 *
 * Deletes the principal +name+ from the Kerberos database.
 */
static VALUE rkadm5_delete_principal(VALUE self, VALUE v_user){
  RUBY_KADM5* ptr;
  char* user;
  krb5_error_code kerror;

  Data_Get_Struct(self, RUBY_KADM5, ptr);
  Check_Type(v_user, T_STRING);
  user = StringValuePtr(v_user);

  if(!ptr->ctx)
    rb_raise(cKadm5Exception, "no context has been established");

  kerror = krb5_parse_name(ptr->ctx, user, &ptr->princ);

  if(kerror)
    rb_raise(cKadm5Exception, "krb5_parse_name: %s", error_message(kerror));

  kerror = kadm5_delete_principal(ptr->handle, ptr->princ);

  if(kerror)
    rb_raise(cKadm5Exception, "kadm5_delete_principal: %s", error_message(kerror));

  return self;
}

/*
 * call-seq:
 *   kadm5.close
 *
 * Closes the kadm5 object. Specifically, it frees the principal and context
 * associated with the kadm5 object, as well as the server handle.
 *
 * Any attempt to call a method on a kadm5 object after it has been closed
 * will fail with an error message indicating a lack of context.
 */
static VALUE rkadm5_close(VALUE self){
  RUBY_KADM5* ptr;
  Data_Get_Struct(self, RUBY_KADM5, ptr);

  if(ptr->princ)
    krb5_free_principal(ptr->ctx, ptr->princ);

  if(ptr->ctx)
    krb5_free_context(ptr->ctx);

  ptr->ctx    = NULL;
  ptr->princ  = NULL;
  ptr->handle = NULL;

  return self;
}

/*
 * call-seq:
 *   kadm5.get_principal(principal_name)
 *
 * Returns a Struct::Principal object for +principal_name+ containing various
 * bits of information regarding that principal, such as policy, attributes,
 * expiration information, etc.
 */
static VALUE rkadm5_get_principal(VALUE self, VALUE v_user){
  RUBY_KADM5* ptr;
  VALUE v_struct;
  char* user;
  char* name;
  int mask;
  kadm5_principal_ent_rec ent;
  krb5_error_code kerror;

  Data_Get_Struct(self, RUBY_KADM5, ptr);
  Check_Type(v_user, T_STRING);
  user = StringValuePtr(v_user);

  memset(&ent, 0, sizeof(ent));

  if(!ptr->ctx)
    rb_raise(cKadm5Exception, "no context has been established");

  kerror = krb5_parse_name(ptr->ctx, user, &ptr->princ);

  if(kerror)
    rb_raise(cKadm5Exception, "krb5_parse_name: %s", error_message(kerror));

  mask = KADM5_PRINCIPAL_NORMAL_MASK;

  kerror = kadm5_get_principal(
    ptr->handle,
    ptr->princ,
    &ent,
    mask
  );

  if(kerror)
    rb_raise(cKadm5Exception, "kadm5_get_principal: %s", error_message(kerror));

  kerror = krb5_unparse_name(ptr->ctx, ent.mod_name, &name);

  if(kerror)
    rb_raise(cKadm5Exception, "krb5_unparse_name: %s", error_message(kerror));

  v_struct = rb_struct_new(
    sPrincipalStruct,
    v_user,
    ent.princ_expire_time ? rb_time_new(ent.princ_expire_time, 0) : Qnil,
    ent.last_pwd_change ? rb_time_new(ent.last_pwd_change, 0) : Qnil,
    ent.pw_expiration ? rb_time_new(ent.pw_expiration, 0) : Qnil,
    LONG2FIX(ent.max_life),
    rb_str_new2(name),
    ent.mod_date ? rb_time_new(ent.mod_date, 0) : Qnil,
    LONG2FIX(ent.attributes),
    INT2FIX(ent.kvno),
    ent.policy ? rb_str_new2(ent.policy) : Qnil,
    INT2FIX(ent.aux_attributes),
    LONG2FIX(ent.max_renewable_life),
    ent.last_success ? rb_time_new(ent.last_success, 0) : Qnil,
    ent.last_failed ? rb_time_new(ent.last_failed, 0) : Qnil,
    INT2FIX(ent.fail_auth_count)
  );

  rb_obj_freeze(v_struct); // This is readonly data.

  return v_struct;
}

#endif

void Init_krb5_auth(){
  VALUE mKerberos = rb_define_module("Krb5Auth");
  VALUE cKrb5     = rb_define_class_under(mKerberos, "Krb5", rb_cObject);
  cKrb5Exception  = rb_define_class_under(cKrb5, "Exception", rb_eStandardError);

  // Krb5 methods
  rb_define_alloc_func(cKrb5, rkrb5_allocate);
  rb_define_method(cKrb5, "initialize", rkrb5_initialize, 0);

  rb_define_method(cKrb5, "get_default_realm", rkrb5_get_default_realm, 0);
  rb_define_method(cKrb5, "get_init_creds_password", rkrb5_get_init_creds_passwd, 2);
  rb_define_method(cKrb5, "get_default_principal", rkrb5_get_default_principal, 0);
  rb_define_method(cKrb5, "change_password", rkrb5_change_password, 2);
  rb_define_method(cKrb5, "close", rkrb5_close, 0);

  rb_define_alias(cKrb5, "default_realm", "get_default_realm");
  rb_define_alias(cKrb5, "default_principal", "get_default_principal");

#ifdef HAVE_KADM5_ADMIN_H
  // Kadm5 methods
  VALUE cKadm5    = rb_define_class_under(mKerberos, "Kadm5", rb_cObject);
  cKadm5Exception = rb_define_class_under(cKadm5, "Exception", rb_eStandardError);

  rb_define_alloc_func(cKadm5, rkadm5_allocate);
  rb_define_method(cKadm5, "initialize", rkadm5_initialize, 2);

  rb_define_method(cKadm5, "close", rkadm5_close, 0);
  rb_define_method(cKadm5, "create_principal", rkadm5_create_principal, 2);
  rb_define_method(cKadm5, "delete_principal", rkadm5_delete_principal, 1);
  rb_define_method(cKadm5, "get_principal", rkadm5_get_principal, 1);
  rb_define_method(cKadm5, "set_password", rkadm5_set_password, 2);

  sPrincipalStruct = rb_struct_define(
    "Principal",
    "principal",
    "princ_expire_time",
    "last_pwd_change",
    "pw_expiration",
    "max_life",
    "mod_name",
    "mod_date",
    "attributes",
    "kvno",
    "policy",
    "aux_attributes",
    "max_renewable_life",
    "last_success",
    "last_failed",
    "fail_auth_count",
    NULL
  );

  rb_define_const(cKadm5, "DISALLOW_POSTDATED", INT2FIX(KRB5_KDB_DISALLOW_POSTDATED));
  rb_define_const(cKadm5, "DISALLOW_FORWARDABLE", INT2FIX(KRB5_KDB_DISALLOW_FORWARDABLE));
  rb_define_const(cKadm5, "DISALLOW_TGT_BASED", INT2FIX(KRB5_KDB_DISALLOW_TGT_BASED));
  rb_define_const(cKadm5, "DISALLOW_RENEWABLE", INT2FIX(KRB5_KDB_DISALLOW_RENEWABLE));
  rb_define_const(cKadm5, "DISALLOW_PROXIABLE", INT2FIX(KRB5_KDB_DISALLOW_PROXIABLE));
  rb_define_const(cKadm5, "DISALLOW_DUP_SKEY", INT2FIX(KRB5_KDB_DISALLOW_DUP_SKEY));
  rb_define_const(cKadm5, "DISALLOW_ALL_TIX", INT2FIX(KRB5_KDB_DISALLOW_ALL_TIX));
  rb_define_const(cKadm5, "REQUIRES_PRE_AUTH", INT2FIX(KRB5_KDB_REQUIRES_PRE_AUTH));
  rb_define_const(cKadm5, "REQUIRES_HW_AUTH", INT2FIX(KRB5_KDB_REQUIRES_HW_AUTH));
  rb_define_const(cKadm5, "REQUIRES_PWCHANGE", INT2FIX(KRB5_KDB_REQUIRES_PWCHANGE));
  rb_define_const(cKadm5, "DISALLOW_SVR", INT2FIX(KRB5_KDB_DISALLOW_SVR));
  rb_define_const(cKadm5, "PWCHANGE_SERVICE", INT2FIX(KRB5_KDB_PWCHANGE_SERVICE));
  rb_define_const(cKadm5, "SUPPORT_DESMD5", INT2FIX(KRB5_KDB_SUPPORT_DESMD5));
  rb_define_const(cKadm5, "NEW_PRINC", INT2FIX(KRB5_KDB_NEW_PRINC));
#endif

  rb_define_const(cKrb5, "VERSION", rb_str_new2("0.8.2"));
}
