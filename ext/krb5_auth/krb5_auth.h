#ifndef KRB5_AUTH_H_INCLUDED
#define KRB5_AUTH_H_INCLUDED

#include <ruby.h>
#include <krb5.h>
#include <string.h>

#ifdef HAVE_KADM5_ADMIN_H
#include <kadm5/admin.h>
#endif

VALUE mKerberos;
VALUE cKrb5;
VALUE cKrb5Keytab;
VALUE cKrb5KtEntry;
VALUE cKrb5Exception;
VALUE cKadm5;
VALUE cKadm5Exception;
VALUE sPrincipalStruct;

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

#endif
