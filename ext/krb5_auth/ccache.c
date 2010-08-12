#include "krb5_auth.h"

// Free function for the Krb5Auth::Krb5::CCache class.
static void rkrb5_ccache_free(RUBY_KRB5_CCACHE* ptr){
  if(!ptr)
    return;

  if(ptr->ccache)
    krb5_cc_close(ptr->ctx, ptr->ccache);

  if(ptr->principal)
    krb5_free_principal(ptr->ctx, ptr->principal);

  if(ptr->ctx)
    krb5_free_context(ptr->ctx);

  free(ptr);
}

// Allocation function for the Krb5Auth::Krb5::CCache class.
static VALUE rkrb5_ccache_allocate(VALUE klass){
  RUBY_KRB5_CCACHE* ptr = malloc(sizeof(RUBY_KRB5_CCACHE));
  memset(ptr, 0, sizeof(RUBY_KRB5_CCACHE));
  return Data_Wrap_Struct(klass, 0, rkrb5_ccache_free, ptr);
}

/*
 * call-seq:
 *   Krb5Auth::CredentialsCache.new('principal@realm')
 *
 * Creates and returns a new Krb5Auth::CredentialsCache object.
 */
static VALUE rkrb5_ccache_initialize(VALUE self, VALUE v_principal){
  RUBY_KRB5_CCACHE* ptr;
  krb5_error_code kerror;

  Data_Get_Struct(self, RUBY_KRB5_CCACHE, ptr);

  Check_Type(v_principal, T_STRING);

  // Convert the principal name to a principal object
  kerror = krb5_parse_name(
    ptr->ctx,
    StringValuePtr(v_principal),
    &ptr->principal
  );

  if(kerror)
    rb_raise(cKrb5Exception, "krb5_parse_name: %s", error_message(kerror));

  // Initialize the context
  kerror = krb5_init_context(&ptr->ctx);

  if(kerror)
    rb_raise(cKrb5Exception, "krb5_init_context: %s", error_message(kerror));

  // Set the credentials cache using the default cache
  kerror = krb5_cc_default(ptr->ctx, &ptr->ccache);

  if(kerror)
    rb_raise(cKrb5Exception, "krb5_cc_default: %s", error_message(kerror));

  // Initialize the credentials cache
  kerror = krb5_cc_initialize(ptr->ctx, ptr->ccache, ptr->principal);

  if(kerror)
    rb_raise(cKrb5Exception, "krb5_cc_initialize: %s", error_message(kerror));
  
  return self;
}

/*
 * call-seq:
 *   ccache.close
 *   
 * Closes the ccache object. Once the ccache object is closed no more
 * methods may be called on it, or an exception will be raised.
 *
 * Note that unlike ccache.destroy, this does not delete the cache.
 */
static VALUE rkrb5_ccache_close(VALUE self){
  RUBY_KRB5_CCACHE* ptr;

  Data_Get_Struct(self, RUBY_KRB5_CCACHE, ptr);

  if(!ptr->ctx)
    return self;

  if(ptr->ccache)
    krb5_cc_close(ptr->ctx, ptr->ccache);

  if(ptr->principal)
    krb5_free_principal(ptr->ctx, ptr->principal);

  if(ptr->ctx)
    krb5_free_context(ptr->ctx);

  ptr->ccache = NULL;
  ptr->ctx = NULL;
  ptr->principal = NULL;

  return self;
}

/*
 * call-seq:
 *   ccache.default_name
 *
 * Returns the name of the default credentials cache.
 */
static VALUE rkrb5_ccache_default_name(VALUE self){
  RUBY_KRB5_CCACHE* ptr;

  Data_Get_Struct(self, RUBY_KRB5_CCACHE, ptr);

  if(!ptr->ctx)
    rb_raise(cKrb5Exception, "no context has been established");

  return rb_str_new2(krb5_cc_default_name(ptr->ctx));
}

/*
 * call-seq:
 *   ccache.destroy
 *
 * Destroy the credentials cache of the current principal. This also closes
 * the object and it cannot be reused.
 */
static VALUE rkrb5_ccache_destroy(VALUE self){
  RUBY_KRB5_CCACHE* ptr;
  krb5_error_code kerror;

  Data_Get_Struct(self, RUBY_KRB5_CCACHE, ptr);

  if(!ptr->ctx)
    rb_raise(cKrb5Exception, "no context has been established");

  kerror = krb5_cc_destroy(ptr->ctx, ptr->ccache);

  if(kerror)
    rb_raise(cKrb5Exception, "krb5_cc_destroy: %s", error_message(kerror));

  if(ptr->principal)
    krb5_free_principal(ptr->ctx, ptr->principal);

  if(ptr->ctx)
    krb5_free_context(ptr->ctx);

  ptr->ccache = NULL;
  ptr->ctx = NULL;
  ptr->principal = NULL;

  return self;
}

void Init_ccache(){
  /* The Krb5Auth::Krb5::CredentialsCache class encapsulates a Kerberos credentials cache. */
  cKrb5CCache = rb_define_class_under(cKrb5, "CredentialsCache", rb_cObject);

  // Allocation Function
  rb_define_alloc_func(cKrb5CCache, rkrb5_ccache_allocate);

  // Constructor
  rb_define_method(cKrb5CCache, "initialize", rkrb5_ccache_initialize, 1);

  // Instance Methods
  rb_define_method(cKrb5CCache, "close", rkrb5_ccache_close, 0);
  rb_define_method(cKrb5CCache, "default_name", rkrb5_ccache_default_name, 0);
  rb_define_method(cKrb5CCache, "destroy", rkrb5_ccache_destroy, 0);

  // Aliases
  rb_define_alias(cKrb5CCache, "delete", "destroy");
}
