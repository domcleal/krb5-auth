require 'mkmf'

dir_config('krb5_auth', '/usr/local')

have_header('krb5.h')
have_library('krb5')

have_header('kadm5/admin.h')
have_library('kadm5clnt')

create_makefile('krb5_auth')
