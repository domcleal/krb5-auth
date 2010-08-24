#include "krb5_auth.h"

// Free function for the Krb5Auth::Krb5::CCache class.
static void rkadm5_policy_free(RUBY_KADM5_POLICY* ptr){
  if(!ptr)
    return;

  if(ptr->ctx)
    krb5_free_context(ptr->ctx);

  free(ptr);
}

// Allocation function for the Krb5Auth::Kadm5::Policy class.
static VALUE rkadm5_policy_allocate(VALUE klass){
  RUBY_KADM5_POLICY* ptr = malloc(sizeof(RUBY_KADM5_POLICY));
  memset(ptr, 0, sizeof(RUBY_KADM5_POLICY));
  return Data_Wrap_Struct(klass, 0, rkadm5_policy_free, ptr);
}

static VALUE rkadm5_policy_init(VALUE self, VALUE v_policy){
  RUBY_KADM5_POLICY* ptr;
  krb5_error_code kerror;

  Data_Get_Struct(self, RUBY_KADM5_POLICY, ptr);

  Check_Type(v_policy, T_STRING);

  rb_iv_set(self, "@policy", v_policy);
  rb_iv_set(self, "@pw_min_life", Qnil);
  rb_iv_set(self, "@pw_max_life", Qnil);
  rb_iv_set(self, "@pw_min_length", Qnil);
  rb_iv_set(self, "@pw_min_classes", Qnil);
  rb_iv_set(self, "@pw_history_num", Qnil);
  rb_iv_set(self, "@policy_refcnt", Qnil);
  rb_iv_set(self, "@pw_max_fail", Qnil);
  rb_iv_set(self, "@pw_failcnt_interval", Qnil);
  rb_iv_set(self, "@pw_lockout_duration", Qnil);

  return self;
}

void Init_policy(){
  cKadm5Policy = rb_define_class_under(cKadm5, "Policy", rb_cObject);

  // Allocation Function

  rb_define_alloc_func(cKadm5Policy, rkadm5_policy_allocate);

  // Initialization Function

  rb_define_method(cKadm5Policy, "initialize", rkadm5_policy_init, 1);

  // Accessors

  rb_define_attr(cKadm5Policy, "policy", 1, 0);

  // Aliases

  rb_define_alias(cKadm5Policy, "name", "policy");
}
