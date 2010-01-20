require 'mkmf'

dir_config('krb5_auth', '/usr/local/include')

have_header('krb5.h')
have_library('krb5')

if have_header('kadm5/admin.h')
  have_library('kadm5clnt')
end

create_makefile('krb5_auth')
