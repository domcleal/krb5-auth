require 'krb5_auth'

config = Krb5Auth::Kadm5::Config.new
p config

# Sample output

=begin
#<Krb5Auth::Kadm5::Config acl_file="/etc/krb5kdc/kadm5.acl" admin_keytab="FILE:/etc/krb5kdc/kadm5.keytab" admin_server="airtemp.globe.ucar.edu" dict_file=nil enctype=16 expiration=nil flags=128 iprop_enabled=false iprop_logfile="/var/lib/krb5kdc/principal.ulog" iprop_poll_time=120 iprop_port=nil kadmind_port=749 keysalts=168166248 kpasswd_port=464 kvno=nil mkey_name=nil mkey_from_kbd=nil maxlife=nil maxrlife=nil num_keysalts=9 realm="FOO.BAR.COM" stash_file="/etc/krb5kdc/stash" >
=end
