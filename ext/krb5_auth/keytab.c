#include "krb5_auth.h"

// Free function for the Krb5Auth::Krb5::Keytab class.
static void rkrb5_keytab_free(RUBY_KRB5_KEYTAB* ptr){
  if(!ptr)
    return;

  if(ptr->keytab)
    krb5_kt_close(ptr->ctx, ptr->keytab);

  if(ptr->ctx)
    krb5_free_context(ptr->ctx);

  free(ptr);
}

// Allocation function for the Krb5Auth::Krb5::Keytab class.
static VALUE rkrb5_keytab_allocate(VALUE klass){
  RUBY_KRB5_KEYTAB* ptr = malloc(sizeof(RUBY_KRB5_KEYTAB));
  memset(ptr, 0, sizeof(RUBY_KRB5_KEYTAB));
  return Data_Wrap_Struct(klass, 0, rkrb5_keytab_free, ptr);
}

/*
 * call-seq:
 *
 *   keytab.each{ |entry| p entry }
 *
 * Iterates over each entry, and yield the principal name.
 *--
 * TODO: Mixin Enumerable properly.
 */
static VALUE rkrb5_keytab_each(VALUE self){
  RUBY_KRB5_KEYTAB* ptr;
  VALUE v_kt_entry;
  VALUE v_args[0];
  krb5_error_code kerror;
  krb5_kt_cursor cursor;
  krb5_keytab_entry entry;
  char* principal;

  Data_Get_Struct(self, RUBY_KRB5_KEYTAB, ptr); 

  kerror = krb5_kt_start_seq_get(
    ptr->ctx,
    ptr->keytab,
    &cursor
  );

  if(kerror)
    rb_raise(cKrb5Exception, "krb5_kt_start_seq_get: %s", error_message(kerror));

  while((kerror = krb5_kt_next_entry(ptr->ctx, ptr->keytab, &entry, &cursor)) == 0){
    krb5_unparse_name(ptr->ctx, entry.principal, &principal);

    v_kt_entry = rb_class_new_instance(0, v_args, cKrb5KtEntry);

    rb_iv_set(v_kt_entry, "@principal", rb_str_new2(principal));
    rb_iv_set(v_kt_entry, "@timestamp", rb_time_new(entry.timestamp, 0));
    rb_iv_set(v_kt_entry, "@vno", INT2FIX(entry.vno));
    rb_iv_set(v_kt_entry, "@key", INT2FIX(entry.key.enctype));

    rb_yield(v_kt_entry);

    free(principal);

    krb5_kt_free_entry(ptr->ctx, &entry);
  }

  kerror = krb5_kt_end_seq_get(
    ptr->ctx,
    ptr->keytab,
    &cursor
  );

  if(kerror)
    rb_raise(cKrb5Exception, "krb5_kt_end_seq_get: %s", error_message(kerror));

  return self; 
}

/*
 * call-seq:
 *
 *   keytab.default_name
 *
 * Returns the default keytab name.
 */
static VALUE rkrb5_keytab_default_name(VALUE self){
  char default_name[512];
  krb5_error_code kerror;
  RUBY_KRB5_KEYTAB* ptr;
  VALUE v_default_name;

  Data_Get_Struct(self, RUBY_KRB5_KEYTAB, ptr); 
  
  kerror = krb5_kt_default_name(ptr->ctx, default_name, 512);

  if(kerror)
    rb_raise(cKrb5Exception, "krb5_kt_default_name: %s", error_message(kerror));

  v_default_name = rb_str_new2(default_name);

  return v_default_name;
}

static VALUE rkrb5_keytab_close(VALUE self){
  RUBY_KRB5_KEYTAB* ptr;

  Data_Get_Struct(self, RUBY_KRB5_KEYTAB, ptr);

  if(ptr->ctx)
    krb5_free_cred_contents(ptr->ctx, &ptr->creds);

  if(ptr->ctx)
    krb5_free_context(ptr->ctx);

  ptr->ctx = NULL;

  return Qtrue;
}

/*
 * call-seq:
 *   Krb5Auth::Krb5::Keytab.new(name = nil)
 *
 * Creates and returns a new Krb5Auth::Krb5::Keytab object. This initializes
 * the context and keytab for future method calls on that object.
 *
 * A keytab file +name+ may be provided. If not, the system's default keytab
 * name is used. If a +name+ is provided it must be in the form 'type:residual'
 * where 'type' is a type known to the Kerberos library.
 *
 * Example:
 *
 *   keytab = Krb5Auth::Krb5::Keytab.new
 *   keytab = Krb5Auth::Krb5::Keytab.new('FILE:/etc/krb5.keytab')
 */
static VALUE rkrb5_keytab_initialize(int argc, VALUE* argv, VALUE self){
  RUBY_KRB5_KEYTAB* ptr;
  krb5_error_code kerror;
  char keytab_name[512];
  VALUE v_keytab_name;

  rb_scan_args(argc, argv, "01", &v_keytab_name);

  Data_Get_Struct(self, RUBY_KRB5_KEYTAB, ptr); 

  kerror = krb5_init_context(&ptr->ctx); 

  if(kerror)
    rb_raise(cKrb5Exception, "krb5_init_context: %s", error_message(kerror));

  // Use the default keytab name if one isn't provided.
  if(NIL_P(v_keytab_name)){
    kerror = krb5_kt_default_name(ptr->ctx, keytab_name, 512);

    if(kerror)
      rb_raise(cKrb5Exception, "krb5_kt_default_name: %s", error_message(kerror));
  } 
  else{
    Check_Type(v_keytab_name, T_STRING);
    strncpy(keytab_name, StringValuePtr(v_keytab_name), 512);
  }

  kerror = krb5_kt_resolve(
    ptr->ctx,
    keytab_name,
    &ptr->keytab      
  );

  if(kerror)
    rb_raise(cKrb5Exception, "krb5_kt_resolve: %s", error_message(kerror));
  
  return self;
}

// Singleton Methods

/*
 * call-seq:
 *   Krb5Auth::Krb5::Keytab.foreach(keytab = nil){ |entry|
 *     puts entry.inspect
 *   }
 *
 * Iterate over each entry in the +keytab+ and yield a Krb5::Keytab::Entry
 * object for each entry found.
 *
 * If no +keytab+ is provided, then the default keytab is used.
 */
static VALUE rkrb5_s_keytab_foreach(int argc, VALUE* argv, VALUE klass){
  RUBY_KRB5_KEYTAB* ptr;
  VALUE v_kt_entry;
  VALUE v_keytab_name;
  VALUE v_args[0];
  krb5_error_code kerror;
  krb5_kt_cursor cursor;
  krb5_keytab keytab;
  krb5_keytab_entry entry;
  krb5_context context;
  char* principal;
  char keytab_name[512];

  rb_scan_args(argc, argv, "01", &v_keytab_name);

  kerror = krb5_init_context(&context); 

  if(kerror)
    rb_raise(cKrb5Exception, "krb5_init_context: %s", error_message(kerror));

  // Use the default keytab name if one isn't provided.
  if(NIL_P(v_keytab_name)){
    kerror = krb5_kt_default_name(context, keytab_name, 512);

    if(kerror){
      rb_raise(cKrb5Exception, "krb5_kt_default_name: %s", error_message(kerror));

      if(context)
        krb5_free_context(context);
    }
  } 
  else{
    Check_Type(v_keytab_name, T_STRING);
    strncpy(keytab_name, StringValuePtr(v_keytab_name), 512);
  }

  kerror = krb5_kt_resolve(
    context,
    keytab_name,
    &keytab
  );

  if(kerror){
    rb_raise(cKrb5Exception, "krb5_kt_resolve: %s", error_message(kerror));

    if(context)
      krb5_free_context(context);
  }

  kerror = krb5_kt_start_seq_get(
    context,
    keytab,
    &cursor
  );

  if(kerror){
    rb_raise(cKrb5Exception, "krb5_kt_start_seq_get: %s", error_message(kerror));

    if(context)
      krb5_free_context(context);

    if(keytab)
      krb5_kt_close(context, keytab);
  }

  while((kerror = krb5_kt_next_entry(context, keytab, &entry, &cursor)) == 0){
    krb5_unparse_name(context, entry.principal, &principal);

    v_kt_entry = rb_class_new_instance(0, v_args, cKrb5KtEntry);

    rb_iv_set(v_kt_entry, "@principal", rb_str_new2(principal));
    rb_iv_set(v_kt_entry, "@timestamp", rb_time_new(entry.timestamp, 0));
    rb_iv_set(v_kt_entry, "@vno", INT2FIX(entry.vno));
    rb_iv_set(v_kt_entry, "@key", INT2FIX(entry.key.enctype));

    rb_yield(v_kt_entry);

    free(principal);

    krb5_kt_free_entry(context, &entry);
  }

  kerror = krb5_kt_end_seq_get(
    context,
    keytab,
    &cursor
  );

  if(kerror){
    rb_raise(cKrb5Exception, "krb5_kt_end_seq_get: %s", error_message(kerror));

    if(context)
      krb5_free_context(context);

    if(keytab)
      krb5_kt_close(context, keytab);
  }

  if(keytab)
    krb5_kt_close(context, keytab);

  if(context)
    krb5_free_context(context);

  return Qnil;
}

void Init_keytab(){
  /* The Krb5Auth::Krb5::Keytab class encapsulates a Kerberos keytab. */
  cKrb5Keytab = rb_define_class_under(cKrb5, "Keytab", rb_cObject);

  // Allocation Function
  rb_define_alloc_func(cKrb5Keytab, rkrb5_keytab_allocate);

  // Constructor
  rb_define_method(cKrb5Keytab, "initialize", rkrb5_keytab_initialize, -1);

  // Singleton Methods
  rb_define_singleton_method(cKrb5Keytab, "foreach", rkrb5_s_keytab_foreach, -1);

  // Instance Methods
  rb_define_method(cKrb5Keytab, "default_name", rkrb5_keytab_default_name, 0);
  rb_define_method(cKrb5Keytab, "close", rkrb5_keytab_close, 0);
  rb_define_method(cKrb5Keytab, "each", rkrb5_keytab_each, 0);
}
