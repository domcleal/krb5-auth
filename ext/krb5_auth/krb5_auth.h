#ifndef KRB5_AUTH_H_INCLUDED
#define KRB5_AUTH_H_INCLUDED

#include <ruby.h>
#include <krb5.h>
#include <string.h>

#ifdef HAVE_KADM5_ADMIN_H
#include <kadm5/admin.h>
#endif

// Function Prototypes
void Init_context();
void Init_kadm5();
void Init_principal();
void Init_keytab();
void Init_keytab_entry();
void Init_ccache();

static VALUE rb_hash_aref2(VALUE, char*);

// Variable declarations
VALUE mKerberos;
VALUE cKrb5;
VALUE cKrb5Context;
VALUE cKrb5Keytab;
VALUE cKrb5KtEntry;
VALUE cKrb5Exception;
VALUE cKrb5Principal;
VALUE cKadm5;
VALUE cKadm5Exception;
VALUE cKrb5CCache;
VALUE sPrincipalStruct;

// Krb5Auth::Krb5
typedef struct {
  krb5_context ctx;
  krb5_creds creds;
  krb5_principal princ;
  krb5_keytab keytab;
} RUBY_KRB5;

// Krb5Auth::Context
typedef struct {
  krb5_context ctx;
  krb5_enctype etypes;
} RUBY_KRB5_CONTEXT;

// Krb5Auth::Kadm5
typedef struct {
  krb5_context ctx;
  krb5_principal princ;
  void* handle;
} RUBY_KADM5;

// Krb5Auth::Krb5::Keytab::Entry
typedef struct {
  krb5_principal principal;
  krb5_timestamp timestamp;
  krb5_kvno vno;
  krb5_keyblock key;
} RUBY_KRB5_KT_ENTRY;

// Krb5Auth::Krb5::Keytab
typedef struct {
  krb5_context ctx;
  krb5_creds creds;
  krb5_keytab keytab;
} RUBY_KRB5_KEYTAB;

typedef struct {
  krb5_principal principal;
} RUBY_KRB5_PRINC;

typedef struct {
  krb5_context ctx;
  krb5_ccache ccache;
  krb5_principal principal;
} RUBY_KRB5_CCACHE;

#ifndef __RB_HASH_AREF2__
#define __RB_HASH_AREF2__
// Get a hash value by string or symbol.
static VALUE rb_hash_aref2(VALUE v_hash, char* key){
  VALUE v_key, v_value;

  v_key = rb_str_new2(key);
  v_value = rb_hash_aref(v_hash, v_key); 

  if(NIL_P(v_value))
    v_value = rb_hash_aref(v_hash, ID2SYM(rb_intern(key)));

  return v_value;
}
#endif

#endif
