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

/*
 * call-seq:
 *   Krb5Auth::Kadm5::Policy.new(policy_name)
 *
 * Returns a new policy object. Yields itself in block form.
 */
static VALUE rkadm5_policy_init(VALUE self, VALUE v_policy){
  RUBY_KADM5_POLICY* ptr;

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

  if(rb_block_given_p())
    rb_yield(self);

  // Set the underlying structure values

  ptr->policy.policy = StringValuePtr(v_policy);

  if(RTEST(rb_iv_get(self, "@pw_min_life")))
    ptr->policy.pw_min_life = NUM2LONG(rb_iv_get(self, "@pw_min_life"));

  if(RTEST(rb_iv_get(self, "@pw_max_life")))
    ptr->policy.pw_max_life = NUM2LONG(rb_iv_get(self, "@pw_max_life"));

  if(RTEST(rb_iv_get(self, "@pw_min_length")))
    ptr->policy.pw_min_length = NUM2LONG(rb_iv_get(self, "@pw_min_length"));

  if(RTEST(rb_iv_get(self, "@pw_min_classes")))
    ptr->policy.pw_min_length = NUM2LONG(rb_iv_get(self, "@pw_min_classes"));

  if(RTEST(rb_iv_get(self, "@pw_history_num")))
    ptr->policy.pw_history_num = NUM2LONG(rb_iv_get(self, "@pw_history_num"));

  if(RTEST(rb_iv_get(self, "@policy_refcnt")))
    ptr->policy.pw_history_num = NUM2LONG(rb_iv_get(self, "@policy_refcnt"));

  if(RTEST(rb_iv_get(self, "@pw_max_fail")))
    ptr->policy.pw_history_num = NUM2LONG(rb_iv_get(self, "@pw_max_fail"));

  if(RTEST(rb_iv_get(self, "@pw_failcnt_interval")))
    ptr->policy.pw_history_num = NUM2LONG(rb_iv_get(self, "@pw_failcnt_interval"));

  if(RTEST(rb_iv_get(self, "@pw_lockout_duration")))
    ptr->policy.pw_history_num = NUM2LONG(rb_iv_get(self, "@pw_lockout_duration"));

  return self;
}

/*
 * call-seq:
 *   policy.pw_min_life = 1000
 *
 * Set the minimum password lifetime, in seconds.
 */
static VALUE rkadm5_policy_set_pw_min_life(VALUE self, VALUE v_num){
  RUBY_KADM5_POLICY* ptr;
  Data_Get_Struct(self, RUBY_KADM5_POLICY, ptr);

  if(!NIL_P(v_num)){
    Check_Type(v_num, T_FIXNUM);
    rb_iv_set(self, "@pw_min_life", LONG2FIX(v_num));
  }

  return v_num;
}

/*
 * call-seq:
 *   policy.pw_max_life = 1000
 *
 * Set the maximum password lifetime, in seconds.
 */
static VALUE rkadm5_policy_set_pw_max_life(VALUE self, VALUE v_num){
  RUBY_KADM5_POLICY* ptr;
  Data_Get_Struct(self, RUBY_KADM5_POLICY, ptr);

  if(!NIL_P(v_num)){
    Check_Type(v_num, T_FIXNUM);
    rb_iv_set(self, "@pw_max_life", LONG2FIX(v_num));
  }

  return v_num;
}

/*
 * call-seq:
 *   policy.pw_min_length = 1000
 *
 * Set the minimum password length.
 */
static VALUE rkadm5_policy_set_pw_min_length(VALUE self, VALUE v_num){
  RUBY_KADM5_POLICY* ptr;
  Data_Get_Struct(self, RUBY_KADM5_POLICY, ptr);

  if(!NIL_P(v_num)){
    Check_Type(v_num, T_FIXNUM);
    rb_iv_set(self, "@pw_min_length", LONG2FIX(v_num));
  }

  return v_num;
}

void Init_policy(){
  /* The Krb5Auth::Kadm5::Policy class encapsulates a Kerberos policy. */
  cKadm5Policy = rb_define_class_under(cKadm5, "Policy", rb_cObject);

  // Allocation Function

  rb_define_alloc_func(cKadm5Policy, rkadm5_policy_allocate);

  // Initialization Function

  rb_define_method(cKadm5Policy, "initialize", rkadm5_policy_init, 1);

  // Instance Methods
  rb_define_method(cKadm5Policy, "pw_min_life=", rkadm5_policy_set_pw_min_life, 1);
  rb_define_method(cKadm5Policy, "pw_max_life=", rkadm5_policy_set_pw_max_life, 1);
  rb_define_method(cKadm5Policy, "pw_min_length=", rkadm5_policy_set_pw_min_length, 1);

  // Accessors

  /* The name of the policy. */
  rb_define_attr(cKadm5Policy, "policy", 1, 0);

  /* The minimum password lifetime, in seconds. */
  rb_define_attr(cKadm5Policy, "pw_min_life", 1, 0);

  /* The maximum duration of a password, in seconds. */
  rb_define_attr(cKadm5Policy, "pw_max_life", 1, 0);

  /* The minimum password length. */
  rb_define_attr(cKadm5Policy, "pw_min_length", 1, 0);

  /* The minimum number of character classes (1-5). */
  rb_define_attr(cKadm5Policy, "pw_min_classes", 1, 1);

  /* The number of past passwords that are stored. */
  rb_define_attr(cKadm5Policy, "pw_history_num", 1, 1);

  /* The number of principals currently using this policy. */
  rb_define_attr(cKadm5Policy, "policy_refcnt", 1, 1);

  /* Maximum number of password attempts before lockout. */
  rb_define_attr(cKadm5Policy, "pw_max_fail", 1, 1);

  /* Period after which bad preauthentication count will be reset. */
  rb_define_attr(cKadm5Policy, "pw_failcnt_interval", 1, 1);

  /* Period in which lockout is enforced. A value of 0 requires manual unlocking. */
  rb_define_attr(cKadm5Policy, "pw_lockout_duration", 1, 1);

  // Aliases

  rb_define_alias(cKadm5Policy, "name", "policy");
}
