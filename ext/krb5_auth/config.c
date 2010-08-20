#include "krb5_auth.h"

static void rkadm5_config_free(RUBY_KADM5_CONFIG* ptr){
  if(!ptr)
    return;

  kadm5_free_config_params(ptr->ctx, &ptr->config);

  if(ptr->ctx)
    krb5_free_context(ptr->ctx);


  free(ptr);
}

// Allocation function for the Krb5Auth::Krb5 class.
static VALUE rkadm5_allocate(VALUE klass){
  RUBY_KADM5_CONFIG* ptr = malloc(sizeof(RUBY_KADM5_CONFIG));
  memset(ptr, 0, sizeof(RUBY_KADM5_CONFIG));
  return Data_Wrap_Struct(klass, 0, rkadm5_config_free, ptr);
}

static VALUE rkadm5_config_initialize(VALUE self){
  RUBY_KADM5_CONFIG* ptr;
  krb5_error_code kerror;

  Data_Get_Struct(self, RUBY_KADM5_CONFIG, ptr); 

  kerror = krb5_init_context(&ptr->ctx);

  if(kerror)
    rb_raise(cKrb5Exception, "krb5_init_context: %s", error_message(kerror));

  kerror = kadm5_get_config_params(
    ptr->ctx,
    1,
    &ptr->config,
    &ptr->config
  );

  if(kerror)
    rb_raise(cKrb5Exception, "kadm5_get_config_params: %s", error_message(kerror));

  if(ptr->config.realm)
    rb_iv_set(self, "@realm", rb_str_new2(ptr->config.realm));

  if(ptr->config.admin_server)
    rb_iv_set(self, "@admin_server", rb_str_new2(ptr->config.admin_server));

  if(ptr->config.kadmind_port)
    rb_iv_set(self, "@kadmind_port", INT2FIX(ptr->config.kadmind_port));

  if(ptr->config.kpasswd_port)
    rb_iv_set(self, "@kpasswd_port", INT2FIX(ptr->config.kpasswd_port));

  if(ptr->config.admin_keytab)
    rb_iv_set(self, "@admin_keytab", rb_str_new2(ptr->config.admin_keytab));

  if(ptr->config.acl_file)
  rb_iv_set(self, "@acl_file", rb_str_new2(ptr->config.acl_file));

  if(ptr->config.dict_file)
    rb_iv_set(self, "@dict_file", rb_str_new2(ptr->config.dict_file));

  if(ptr->config.stash_file)
    rb_iv_set(self, "@stash_file", rb_str_new2(ptr->config.stash_file));

  if(ptr->config.mkey_name)
    rb_iv_set(self, "@mkey_name", rb_str_new2(ptr->config.mkey_name));

  if(ptr->config.mkey_from_kbd)
    rb_iv_set(self, "@mkey_from_kbd", INT2FIX(ptr->config.mkey_from_kbd));

  if(ptr->config.mkey_from_kbd)
    rb_iv_set(self, "@mkey_from_kbd", INT2FIX(ptr->config.mkey_from_kbd));

  if(ptr->config.enctype)
    rb_iv_set(self, "@enctype", INT2FIX(ptr->config.enctype));

  if(ptr->config.max_life)
    rb_iv_set(self, "@enctype", INT2FIX(ptr->config.max_life));

  if(ptr->config.max_rlife)
    rb_iv_set(self, "@enctype", INT2FIX(ptr->config.max_rlife));

  if(ptr->config.expiration)
    rb_iv_set(self, "@expiration", rb_time_new(ptr->config.expiration, 0));

  if(ptr->config.flags)
    rb_iv_set(self, "@flags", INT2FIX(ptr->config.flags));

  if(ptr->config.kvno)
    rb_iv_set(self, "@kvno", INT2FIX(ptr->config.kvno));

  if(ptr->config.iprop_enabled)
    rb_iv_set(self, "@iprop_enabled", Qtrue);
  else
    rb_iv_set(self, "@iprop_enabled", Qfalse);

  if(ptr->config.iprop_logfile)
    rb_iv_set(self, "@iprop_logfile", rb_str_new2(ptr->config.iprop_logfile));

  if(ptr->config.iprop_poll_time)
    rb_iv_set(self, "@iprop_poll_time", INT2FIX(ptr->config.iprop_poll_time));

  if(ptr->config.iprop_port)
    rb_iv_set(self, "@iprop_port", INT2FIX(ptr->config.iprop_port));

  return self;
}

void Init_config(){
  cKadm5Config = rb_define_class_under(cKadm5, "Config", rb_cObject);

  // Allocation function

  rb_define_alloc_func(cKadm5Config, rkadm5_allocate);
  
  // Initializer

  rb_define_method(cKadm5Config, "initialize", rkadm5_config_initialize, 0);

  // Accessors

  rb_define_attr(cKadm5Config, "realm", 1, 0);
  rb_define_attr(cKadm5Config, "admin_server", 1, 0);
  rb_define_attr(cKadm5Config, "kadmind_port", 1, 0);
  rb_define_attr(cKadm5Config, "kpasswd_port", 1, 0);
  rb_define_attr(cKadm5Config, "admin_keytab", 1, 0);
  rb_define_attr(cKadm5Config, "acl_file", 1, 0);
  rb_define_attr(cKadm5Config, "dict_file", 1, 0);
  rb_define_attr(cKadm5Config, "stash_file", 1, 0);
  rb_define_attr(cKadm5Config, "mkey_name", 1, 0);
  rb_define_attr(cKadm5Config, "mkey_from_kbd", 1, 0);
  rb_define_attr(cKadm5Config, "enctype", 1, 0);
  rb_define_attr(cKadm5Config, "max_life", 1, 0);
  rb_define_attr(cKadm5Config, "max_rlife", 1, 0);
  rb_define_attr(cKadm5Config, "expiration", 1, 0);
  rb_define_attr(cKadm5Config, "flags", 1, 0);
  rb_define_attr(cKadm5Config, "kvno", 1, 0);
  rb_define_attr(cKadm5Config, "iprop_enabled", 1, 0);
  rb_define_attr(cKadm5Config, "iprop_logfile", 1, 0);
  rb_define_attr(cKadm5Config, "iprop_poll_time", 1, 0);
  rb_define_attr(cKadm5Config, "iprop_port", 1, 0);
}
