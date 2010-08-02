#include "krb5_auth.h"

// Free function for the Krb5Auth::Kadm5 class.
static void rkadm5_free(RUBY_KADM5* ptr){
  if(!ptr)
    return;

  if(ptr->princ)
    krb5_free_principal(ptr->ctx, ptr->princ);

  if(ptr->ctx)
    krb5_free_context(ptr->ctx);

  free(ptr);
}

// Allocation function for the Krb5Auth::Kadm5 class.
static VALUE rkadm5_allocate(VALUE klass){
  RUBY_KADM5* ptr = malloc(sizeof(RUBY_KADM5));
  memset(ptr, 0, sizeof(RUBY_KADM5));
  return Data_Wrap_Struct(klass, 0, rkadm5_free, ptr);
}

/*
 * call-seq:
 *   Krb5Auth::Kadm5.new(:principal => 'name', :password => 'xxxxx')
 *   Krb5Auth::Kadm5.new(:principal => 'name', :keytab => '/path/to/your/keytab')
 *   Krb5Auth::Kadm5.new(:principal => 'name', :keytab => true)
 *
 * Creates and returns a new Krb5Auth::Kadm5 object. A hash argument is
 * accepted that allows you to specify a principal and a password, or
 * a keytab file.
 *
 * If you pass a string as the :keytab value it will attempt to use that file
 * for the keytab. If you pass true as the value it will attempt to use the
 * default keytab file, typically /etc/krb5.keytab.
 *
 * You may also pass the :service option to specify the service name. The
 * default is kadmin/admin.
 */
static VALUE rkadm5_initialize(VALUE self, VALUE v_opts){
  RUBY_KADM5* ptr;
  VALUE v_principal, v_password, v_keytab, v_service;
  char* user;
  char* pass;
  char* keytab;
  char* service;
  krb5_error_code kerror;

  Data_Get_Struct(self, RUBY_KADM5, ptr);
  Check_Type(v_opts, T_HASH);

  v_principal = rb_hash_aref2(v_opts, "principal");

  // Principal must be specified
  if(NIL_P(v_principal))
    rb_raise(rb_eArgError, "principal must be specified");

  Check_Type(v_principal, T_STRING);
  user = StringValuePtr(v_principal);

  v_password = rb_hash_aref2(v_opts, "password");
  v_keytab = rb_hash_aref2(v_opts, "keytab");

  if(RTEST(v_password) && RTEST(v_keytab))
    rb_raise(rb_eArgError, "cannot use both a password and a keytab");

  if(RTEST(v_password)){
    Check_Type(v_password, T_STRING);
    pass = StringValuePtr(v_password);
  }

  v_service = rb_hash_aref2(v_opts, "service");

  if(NIL_P(v_service)){
    service = "kadmin/admin";
  }
  else{
    Check_Type(v_service, T_STRING);
    service = StringValuePtr(v_service);
  }

  // Normally I would wait to initialize the context, but we might need it
  // to get the default keytab file name.
  kerror = krb5_init_context(&ptr->ctx);

  if(kerror)
    rb_raise(cKadm5Exception, "krb5_init_context: %s", error_message(kerror));

  // The docs say I can use NULL to get the default, but reality appears to be otherwise.
  if(RTEST(v_keytab)){
    if(TYPE(v_keytab) == T_TRUE){
      char default_name[MAX_KEYTAB_NAME_LEN];

      kerror = krb5_kt_default_name(ptr->ctx, default_name, MAX_KEYTAB_NAME_LEN);

      if(kerror)
        rb_raise(cKrb5Exception, "krb5_kt_default_name: %s", error_message(kerror));

      keytab = default_name;
    }
    else{
      Check_Type(v_keytab, T_STRING);
      keytab = StringValuePtr(v_keytab);
    }
  }

  if(RTEST(v_password)){
#ifdef KADM5_API_VERSION_3
    kerror = kadm5_init_with_password(
      ptr->ctx,
      user,
      pass,
      //KADM5_ADMIN_SERVICE,
      service,
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
      //KADM5_ADMIN_SERVICE,
      service,
      NULL,
      KADM5_STRUCT_VERSION,
      KADM5_API_VERSION_2,
      NULL,
      &ptr->handle
    );
#endif

    if(kerror)
      rb_raise(cKadm5Exception, "kadm5_init_with_password: %s", error_message(kerror));
  }
  else if(RTEST(v_keytab)){
#ifdef KADM5_API_VERSION_3
    kerror = kadm5_init_with_skey(
      ptr->ctx,
      user,
      keytab,
      service,
      NULL,
      KADM5_STRUCT_VERSION,
      KADM5_API_VERSION_3,
      NULL,
      &ptr->handle
    );
#else
    kerror = kadm5_init_with_skey(
      user,
      keytab,
      service,
      NULL,
      KADM5_STRUCT_VERSION,
      KADM5_API_VERSION_2,
      NULL,
      &ptr->handle
    );
#endif

    if(kerror)
      rb_raise(cKadm5Exception, "kadm5_init_with_skey: %s", error_message(kerror));
  }
  else{
    // TODO: Credentials cache.
  }

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

void Init_kadm5(){
  cKadm5 = rb_define_class_under(mKerberos, "Kadm5", rb_cObject);
  cKadm5Exception = rb_define_class_under(cKadm5, "Exception", rb_eStandardError);

  rb_define_alloc_func(cKadm5, rkadm5_allocate);
  rb_define_method(cKadm5, "initialize", rkadm5_initialize, 1);

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

}
