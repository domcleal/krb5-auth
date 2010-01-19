#include <ruby.h>
#include <krb5.h>
#include <strings.h>
#include <errno.h>

VALUE cKrb5Exception;

typedef struct {
  krb5_context ctx;
  krb5_creds creds;
  krb5_principal princ;
} RUBY_KRB5;

static void rkrb5_free(RUBY_KRB5* ptr){
  if(!ptr)
    return;

  if(ptr->ctx)
    krb5_free_cred_contents(ptr->ctx, &ptr->creds);

  if(ptr && ptr->princ)
    krb5_free_principal(ptr->ctx, ptr->princ);

  if(ptr && ptr->ctx)
    krb5_free_context(ptr->ctx);

  if(ptr)
    free(ptr);
}

static VALUE rkrb5_allocate(VALUE klass){
  RUBY_KRB5* ptr = malloc(sizeof(RUBY_KRB5));
  memset(ptr, 0, sizeof(RUBY_KRB5));
  return Data_Wrap_Struct(klass, 0, rkrb5_free, ptr);
}

static VALUE rkrb5_initialize(VALUE self){
  RUBY_KRB5* ptr;
  Data_Get_Struct(self, RUBY_KRB5, ptr); 

  errno = krb5_init_context(&ptr->ctx); 

  if(errno)
    rb_raise(cKrb5Exception, "krb5_init_context: %s", error_message(errno));

  return self;
}

static VALUE rkrb5_get_default_realm(VALUE self){
  RUBY_KRB5* ptr;
  char* realm;

  Data_Get_Struct(self, RUBY_KRB5, ptr); 

  errno = krb5_get_default_realm(ptr->ctx, &realm);

  if(errno)
    rb_raise(cKrb5Exception, "krb5_get_default_realm: %s", error_message(errno));

  return rb_str_new2(realm);
}

static VALUE rkrb5_change_password(VALUE self, VALUE v_old, VALUE v_new){
  Check_Type(v_old, T_STRING);
  Check_Type(v_new, T_STRING);

  RUBY_KRB5* ptr;
  krb5_data result_string;
  krb5_data pw_result_string;

  int pw_result;
  char* old_passwd = StringValuePtr(v_old);
  char* new_passwd = StringValuePtr(v_new);

  Data_Get_Struct(self, RUBY_KRB5, ptr); 

  if(!ptr->ctx)
    rb_raise(cKrb5Exception, "no context has been established"); 

  if(!ptr->princ)
    rb_raise(cKrb5Exception, "no principal has been established"); 

  errno = krb5_get_init_creds_password(
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

  if(errno)
    rb_raise(cKrb5Exception, "krb5_get_init_creds_password: %s", error_message(errno));

  errno = krb5_change_password(
    ptr->ctx,
    &ptr->creds,
    new_passwd,
    &pw_result,
    &pw_result_string,
    &result_string
  );

  if(errno)
    rb_raise(cKrb5Exception, "krb5_change_password: %s", error_message(errno));

  return Qtrue;
}

static VALUE rkrb5_get_init_creds_passwd(VALUE self, VALUE v_user, VALUE v_pass){
  Check_Type(v_user, T_STRING);
  Check_Type(v_pass, T_STRING);

  RUBY_KRB5* ptr;
  char* user = StringValuePtr(v_user);
  char* pass = StringValuePtr(v_pass);

  Data_Get_Struct(self, RUBY_KRB5, ptr); 

  errno = krb5_parse_name(ptr->ctx, user, &ptr->princ); 

  if(errno)
    rb_raise(cKrb5Exception, "krb5_parse_name: %s", error_message(errno));

  errno = krb5_get_init_creds_password(
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

  if(errno)
    rb_raise(cKrb5Exception, "krb5_get_init_creds_password: %s", error_message(errno));

  return Qtrue;
}

// This is a stub. Ruby will automatically free the object.
static VALUE rkrb5_close(VALUE self){
  return self;
}

static VALUE rkrb5_get_default_principal(VALUE self){
  char* princ_name;
  RUBY_KRB5* ptr;
  krb5_ccache ccache;  

  Data_Get_Struct(self, RUBY_KRB5, ptr); 

  // Get the default credentials cache
  errno = krb5_cc_default(ptr->ctx, &ccache);

  if(errno)
    rb_raise(cKrb5Exception, "krb5_cc_default: %s", error_message(errno));

  errno = krb5_cc_get_principal(ptr->ctx, ccache, &ptr->princ);

  if(errno){
    krb5_cc_close(ptr->ctx, ccache);
    rb_raise(cKrb5Exception, "krb5_cc_get_principal: %s", error_message(errno));
  }

  krb5_cc_close(ptr->ctx, ccache);

  errno = krb5_unparse_name(ptr->ctx, ptr->princ, &princ_name);

  if(errno)
    rb_raise(cKrb5Exception, "krb5_cc_default: %s", error_message(errno));

  return rb_str_new2(princ_name);
}

void Init_krb5_auth(){
  VALUE mKerberos = rb_define_module("Krb5Auth");
  VALUE cKrb5     = rb_define_class_under(mKerberos, "Krb5", rb_cObject);
  cKrb5Exception  = rb_define_class_under(cKrb5, "Exception", rb_eStandardError);

  rb_define_alloc_func(cKrb5, rkrb5_allocate);

  rb_define_method(cKrb5, "initialize", rkrb5_initialize, 0);
  rb_define_method(cKrb5, "get_default_realm", rkrb5_get_default_realm, 0);
  rb_define_method(cKrb5, "get_init_creds_password", rkrb5_get_init_creds_passwd, 2);
  rb_define_method(cKrb5, "get_default_principal", rkrb5_get_default_principal, 0);
  rb_define_method(cKrb5, "change_password", rkrb5_change_password, 2);
  rb_define_method(cKrb5, "close", rkrb5_close, 0);

  rb_define_const(cKrb5, "VERSION", rb_str_new2("0.8.0"));
}
