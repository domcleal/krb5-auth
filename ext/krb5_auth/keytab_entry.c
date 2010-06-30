#include "krb5_auth.h"

// Free function for the Krb5Auth::Krb5::Keytab::Entry class.
static void rkrb5_kt_entry_free(RUBY_KRB5_KT_ENTRY* ptr){
  if(!ptr)
    return;

  free(ptr);
}

// Allocation function for the Krb5Auth::Krb5::Keytab::Entry class.
static VALUE rkrb5_kt_entry_allocate(VALUE klass){
  RUBY_KRB5_KT_ENTRY* ptr = malloc(sizeof(RUBY_KRB5_KT_ENTRY));
  memset(ptr, 0, sizeof(RUBY_KRB5_KT_ENTRY));
  return Data_Wrap_Struct(klass, 0, rkrb5_kt_entry_free, ptr);
}

/*
 * call-seq:
 *
 *   Krb5Auth::Krb5::Keytab::Entry.new
 *
 * Creates and returns a new Krb5Auth::Krb5::Keytab::Entry object. These
 * objects are what is typically returned from the various Krb5::Keytab
 * methods.
 */
static VALUE rkrb5_kt_entry_initialize(VALUE self){
  RUBY_KRB5_KT_ENTRY* ptr;
  Data_Get_Struct(self, RUBY_KRB5_KT_ENTRY, ptr); 
  return self;
}

void Init_keytab_entry(){
  // The Krb5::Krb5::Keytab::Entry class encapsulates a Kerberos keytab entry.
  cKrb5KtEntry = rb_define_class_under(cKrb5Keytab, "Entry", rb_cObject);

  // Allocation function
  rb_define_alloc_func(cKrb5KtEntry, rkrb5_kt_entry_allocate);

  // Constructor
  rb_define_method(cKrb5KtEntry, "initialize", rkrb5_kt_entry_initialize, 0);

  // Krb5::Keytab::Entry Methods
  rb_define_attr(cKrb5KtEntry, "principal", 1, 1);
  rb_define_attr(cKrb5KtEntry, "timestamp", 1, 1);
  rb_define_attr(cKrb5KtEntry, "vno", 1, 1);
  rb_define_attr(cKrb5KtEntry, "key", 1, 1);
}
