#include <krb5_auth.h>

VALUE cKadm5;
VALUE cKadm5Exception;
VALUE cKadm5PrincipalNotFoundException;

// Prototype
static VALUE rkadm5_close(VALUE);

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
  char* pass = NULL;
  char* keytab = NULL;
  char* service = NULL;
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

  if(rb_block_given_p()){
    rb_ensure(rb_yield, self, rkadm5_close, self);
    return Qnil;
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
 *   kadm5.create_principal(principal)
 *
 * Creates a new principal +name+ with an initial password of +password+.
 *--
 * TODO: Allow a Principal object to be passed in as an argument.
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

  if(ptr->handle)
    kadm5_destroy(ptr->handle);

  ptr->ctx    = NULL;
  ptr->princ  = NULL;
  ptr->handle = NULL;

  return self;
}

// Private function for creating a Principal object from a entry record.
static VALUE create_principal_from_entry(VALUE v_name, RUBY_KADM5* ptr, kadm5_principal_ent_rec* ent){
  krb5_error_code kerror;
  VALUE v_principal;
  VALUE v_args[1];

  v_args[0] = v_name;

  v_principal = rb_class_new_instance(1, v_args, cKrb5Principal);

  rb_iv_set(v_principal, "@attributes", LONG2FIX(ent->attributes));
  rb_iv_set(v_principal, "@aux_attributes", INT2FIX(ent->aux_attributes));

  if(ent->princ_expire_time)
    rb_iv_set(v_principal, "@expire_time", rb_time_new(ent->princ_expire_time, 0));

  rb_iv_set(v_principal, "@fail_auth_count", INT2FIX(ent->fail_auth_count));
  rb_iv_set(v_principal, "@kvno", INT2FIX(ent->kvno));

  if(ent->last_failed)
    rb_iv_set(v_principal, "@last_failed", rb_time_new(ent->last_failed, 0));

  if(ent->last_failed)
    rb_iv_set(v_principal, "@last_password_change", rb_time_new(ent->last_pwd_change, 0));

  if(ent->last_failed)
    rb_iv_set(v_principal, "@last_success", rb_time_new(ent->last_success, 0));

  rb_iv_set(v_principal, "@max_life", LONG2FIX(ent->max_life));
  rb_iv_set(v_principal, "@max_renewable_life", LONG2FIX(ent->max_renewable_life));

  if(ent->mod_date)
    rb_iv_set(v_principal, "@mod_date", rb_time_new(ent->mod_date, 0));

  if(ent->mod_name){
    char* mod_name;
    kerror = krb5_unparse_name(ptr->ctx, ent->mod_name, &mod_name);

    if(kerror)
      rb_raise(cKadm5Exception, "krb5_unparse_name: %s", error_message(kerror));

    rb_iv_set(v_principal, "@mod_name", rb_str_new2(mod_name));
  }

  if(ent->pw_expiration)
    rb_iv_set(v_principal, "@password_expiration", rb_time_new(ent->pw_expiration, 0));

  if(ent->policy)
    rb_iv_set(v_principal, "policy", rb_str_new2(ent->policy));

  return v_principal;
}

/*
 * call-seq:
 *   kadm5.find_principal(principal_name)
 *
 * Returns a Principal object for +principal_name+ containing various bits
 * of information regarding that principal, such as policy, attributes,
 * expiration information, etc.
 *
 * Unlike the get_principal method, this method returns nil if the principal
 * cannot be found instead of raising an error.
 */
static VALUE rkadm5_find_principal(VALUE self, VALUE v_user){
  RUBY_KADM5* ptr;
  VALUE v_principal;
  char* user;
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

  // Return nil if not found instead of raising an error.
  if(kerror){
    if(kerror == KADM5_UNK_PRINC)
      v_principal = Qnil;
    else
      rb_raise(cKadm5Exception, "kadm5_get_principal: %s", error_message(kerror));
  }
  else{
    v_principal = create_principal_from_entry(v_user, ptr, &ent);
  }

  return v_principal;
}

/*
 * call-seq:
 *   kadm5.get_principal(principal_name)
 *
 * Returns a Principal object for +principal_name+ containing various bits
 * of information regarding that principal, such as policy, attributes,
 * expiration information, etc.
 *
 * If the +principal_name+ cannot be found then a PrincipalNotFoundException
 * is raised.
 */
static VALUE rkadm5_get_principal(VALUE self, VALUE v_user){
  RUBY_KADM5* ptr;
  VALUE v_principal;
  char* user;
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

  if(kerror){
    if(kerror == KADM5_UNK_PRINC)
      rb_raise(cKadm5PrincipalNotFoundException, "principal not found");
    else
      rb_raise(cKadm5Exception, "kadm5_get_principal: %s", error_message(kerror));
  }

  v_principal = create_principal_from_entry(v_user, ptr, &ent);

  return v_principal;
}

/*
 * call-seq:
 *   kadm5.create_policy(policy)
 *
 * Creates a new Kerberos policy based on the Policy object.
 *
 * Example:
 *
 *   # Using a Policy object
 *   policy = Krb5Auth::Kadm5::Policy.new(:name => 'test', :min_length => 5)
 *   kadm5.create_policy(policy)
 *
 *   # Using a hash
 *   kadm5.create_policy(:name => 'test', :min_length => 5)
 */
static VALUE rkadm5_create_policy(VALUE self, VALUE v_policy){
  RUBY_KADM5* ptr;
  kadm5_ret_t kerror;
  kadm5_policy_ent_rec ent;
  long mask = KADM5_POLICY;
  VALUE v_name, v_min_classes, v_min_life, v_max_life, v_min_length, v_history_num;

  Data_Get_Struct(self, RUBY_KADM5, ptr);

  // Allow a hash or a Policy object
  if(rb_obj_is_kind_of(v_policy, rb_cHash)){
    VALUE v_args[1];
    v_args[0] = v_policy;
    v_policy = rb_class_new_instance(1, v_args, cKadm5Policy);
  }

  v_name        = rb_iv_get(v_policy, "@policy");
  v_min_classes = rb_iv_get(v_policy, "@min_classes");
  v_min_length  = rb_iv_get(v_policy, "@min_length");
  v_min_life    = rb_iv_get(v_policy, "@min_life");
  v_max_life    = rb_iv_get(v_policy, "@max_life");
  v_history_num = rb_iv_get(v_policy, "@history_num");

  ent.policy = StringValuePtr(v_name);

  if(RTEST(v_min_classes)){
    mask |= KADM5_PW_MIN_CLASSES;
    ent.pw_min_classes = NUM2LONG(v_min_classes);
  }
    
  if(RTEST(v_min_length)){
    mask |= KADM5_PW_MIN_LENGTH;
    ent.pw_min_length = NUM2LONG(v_min_length);
  }

  if(RTEST(v_min_life)){
    mask |= KADM5_PW_MIN_LIFE;
    ent.pw_min_life = NUM2LONG(v_min_life);
  }

  if(RTEST(v_max_life)){
    mask |= KADM5_PW_MAX_LIFE;
    ent.pw_max_life = NUM2LONG(v_max_life);
  }

  if(RTEST(v_history_num)){
    mask |= KADM5_PW_HISTORY_NUM;
    ent.pw_max_life = NUM2LONG(v_history_num);
  }

  kerror = kadm5_create_policy(ptr->handle, &ent, mask);

  if(kerror)
    rb_raise(cKadm5Exception, "kadm5_create_policy: %s (%li)", error_message(kerror), kerror);

  return self;
}

/*
 * call-seq:
 *   kadm5.delete_policy(name)
 *
 * Deletes the Kerberos policy +name+.
 *
 * Example:
 *
 *   kadm5.delete_policy('test')
 */
static VALUE rkadm5_delete_policy(VALUE self, VALUE v_policy){
  RUBY_KADM5* ptr;
  kadm5_ret_t kerror;
  char* policy;

  Data_Get_Struct(self, RUBY_KADM5, ptr);

  policy = StringValuePtr(v_policy);

  kerror = kadm5_delete_policy(ptr->handle, policy);

  if(kerror)
    rb_raise(cKadm5Exception, "kadm5_delete_policy: %s (%li)", error_message(kerror), kerror);

  return self;
}

/*
 * call-seq:
 *   kadm5.get_policy(name)
 *
 * Get and return a Policy object for +name+. If the +name+ cannot be found,
 * then an exception is raised.
 *
 * This method is nearly identical to kadm5.find_policy, except that method
 * returns nil if not found.
 */
static VALUE rkadm5_get_policy(VALUE self, VALUE v_name){
  RUBY_KADM5* ptr;
  VALUE v_policy = Qnil;
  kadm5_policy_ent_rec ent;
  kadm5_ret_t kerror;
  char* policy_name;

  Data_Get_Struct(self, RUBY_KADM5, ptr);
  memset(&ent, 0, sizeof(ent));

  if(!ptr->ctx)
    rb_raise(cKadm5Exception, "no context has been established");

  policy_name = StringValuePtr(v_name);

  kerror = kadm5_get_policy(ptr->handle, policy_name, &ent); 

  if(kerror){
    rb_raise(
      cKadm5Exception,
      "kadm5_get_policy: %s (%li)", error_message(kerror), kerror
    );
  }
  else{
    VALUE v_arg[1];
    VALUE v_hash = rb_hash_new();

    rb_hash_aset(v_hash, rb_str_new2("name"), rb_str_new2(ent.policy));
    rb_hash_aset(v_hash, rb_str_new2("min_life"), LONG2FIX(ent.pw_min_life));
    rb_hash_aset(v_hash, rb_str_new2("max_life"), LONG2FIX(ent.pw_max_life));
    rb_hash_aset(v_hash, rb_str_new2("min_length"), LONG2FIX(ent.pw_min_length));
    rb_hash_aset(v_hash, rb_str_new2("min_classes"), LONG2FIX(ent.pw_min_classes));
    rb_hash_aset(v_hash, rb_str_new2("history_num"), LONG2FIX(ent.pw_history_num));

    v_arg[0] = v_hash;

    v_policy = rb_class_new_instance(1, v_arg, cKadm5Policy);
  }

  return v_policy;
}

/*
 * call-seq:
 *   kadm5.find_policy(name)
 *
 * Get and return a Policy object for +name+. If the +name+ cannot be found,
 * then nil is returned.
 *
 * This method is nearly identical to kadm5.get_policy, except that method
 * raises an exception if not found.
 */
static VALUE rkadm5_find_policy(VALUE self, VALUE v_name){
  RUBY_KADM5* ptr;
  VALUE v_policy = Qnil;
  kadm5_policy_ent_rec ent;
  kadm5_ret_t kerror;
  char* policy_name;

  Data_Get_Struct(self, RUBY_KADM5, ptr);
  memset(&ent, 0, sizeof(ent));

  if(!ptr->ctx)
    rb_raise(cKadm5Exception, "no context has been established");

  policy_name = StringValuePtr(v_name);

  kerror = kadm5_get_policy(ptr->handle, policy_name, &ent); 

  // Return nil if not found rather than raising an error.
  if(kerror){
    if(kerror != KADM5_UNK_POLICY){
      rb_raise(
        cKadm5Exception,
        "kadm5_get_policy: %s (%li)", error_message(kerror), kerror
      );
    }
  }
  else{
    VALUE v_arg[1];
    VALUE v_hash = rb_hash_new();

    rb_hash_aset(v_hash, rb_str_new2("name"), rb_str_new2(ent.policy));
    rb_hash_aset(v_hash, rb_str_new2("min_life"), LONG2FIX(ent.pw_min_life));
    rb_hash_aset(v_hash, rb_str_new2("max_life"), LONG2FIX(ent.pw_max_life));
    rb_hash_aset(v_hash, rb_str_new2("min_length"), LONG2FIX(ent.pw_min_length));
    rb_hash_aset(v_hash, rb_str_new2("min_classes"), LONG2FIX(ent.pw_min_classes));
    rb_hash_aset(v_hash, rb_str_new2("history_num"), LONG2FIX(ent.pw_history_num));

    v_arg[0] = v_hash;

    v_policy = rb_class_new_instance(1, v_arg, cKadm5Policy);
  }

  return v_policy;
}

/*
 * call-seq:
 *   kadm5.modify_policy(policy)
 *
 * Modify an existing Kerberos policy using a +policy+ object.
 *
 * Example:
 *
 *   policy = Krb5Auth::Kadm5::Policy.find('test')
 *   policy.max_length = 1024
 *   kadm5.modify_policy(policy)
 */
static VALUE rkadm5_modify_policy(VALUE self, VALUE v_policy){
  RUBY_KADM5* ptr;
  RUBY_KADM5_POLICY* pptr;
  kadm5_ret_t kerror;
  long mask = KADM5_POLICY;

  Data_Get_Struct(self, RUBY_KADM5, ptr);
  Data_Get_Struct(v_policy, RUBY_KADM5_POLICY, pptr);

  if(!ptr->ctx)
    rb_raise(cKadm5Exception, "no context has been established");

  if(pptr->policy.pw_min_classes)
    mask |= KADM5_PW_MIN_CLASSES;

  if(pptr->policy.pw_min_length)
    mask |= KADM5_PW_MIN_LENGTH;

  if(pptr->policy.pw_min_life)
    mask |= KADM5_PW_MIN_LIFE;

  if(pptr->policy.pw_max_life)
    mask |= KADM5_PW_MAX_LIFE;

  kerror = kadm5_modify_policy(ptr->handle, &pptr->policy, mask);

  if(kerror)
    rb_raise(cKadm5Exception, "kadm5_modify_policy: %s (%li)", error_message(kerror), kerror);

  return self;
}

void Init_kadm5(){
  /* The Kadm5 class encapsulates administrative Kerberos functions. */
  cKadm5 = rb_define_class_under(mKerberos, "Kadm5", rb_cObject);

  /* Error typically raised if any of the Kadm5 methods fail. */
  cKadm5Exception = rb_define_class_under(cKadm5, "Exception", rb_eStandardError);

  /* Error raised if a get_principal call cannot find the principal. */
  cKadm5PrincipalNotFoundException = rb_define_class_under(
    cKadm5, "PrincipalNotFoundException", rb_eStandardError
  );

  // Allocation Functions

  rb_define_alloc_func(cKadm5, rkadm5_allocate);

  // Initialization Method

  rb_define_method(cKadm5, "initialize", rkadm5_initialize, 1);

  // Instance Methods

  rb_define_method(cKadm5, "close", rkadm5_close, 0);
  rb_define_method(cKadm5, "create_policy", rkadm5_create_policy, 1);
  rb_define_method(cKadm5, "create_principal", rkadm5_create_principal, 2);
  rb_define_method(cKadm5, "delete_policy", rkadm5_delete_policy, 1);
  rb_define_method(cKadm5, "delete_principal", rkadm5_delete_principal, 1);
  rb_define_method(cKadm5, "find_principal", rkadm5_find_principal, 1);
  rb_define_method(cKadm5, "find_policy", rkadm5_find_policy, 1);
  rb_define_method(cKadm5, "get_policy", rkadm5_get_policy, 1);
  rb_define_method(cKadm5, "get_principal", rkadm5_get_principal, 1);
  rb_define_method(cKadm5, "modify_policy", rkadm5_modify_policy, 1);
  rb_define_method(cKadm5, "set_password", rkadm5_set_password, 2);

  // Constants

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
