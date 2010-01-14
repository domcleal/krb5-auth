require 'mkmf'

dir_config('krb5_auth')

have_header('krb5.h')
have_library('krb5')

create_makefile('krb5_auth')
