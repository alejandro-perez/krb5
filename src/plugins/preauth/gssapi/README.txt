This README file will provide you with enough information to make the plugin
work with most of the configurations.

BUILDING AND INSTALLING THE CODE
-----------------------------------
To build and install the code just follow the standard MIT Kerberos procedure.

./configure && make && make install

Make sure you have enough privileges to perform the "make install" process 
successfully.

CONFIGURING THE GSS-PREAUTH PLUGIN
----------------------------------
You need to indicate where the module is located. In the client, you should 
edit the krb5.conf file and include the following:

[plugins]
	clpreauth = {
        module = gssapi:/user/local/lib/krb5/plugins/preauth/gssapi.so
    }

In the KDC, you should edit the kdc.conf file and include the following:

[plugins]
    kdcpreauth = {
        module = gssapi:/usr/local/lib/krb5/plugins/preauth/gssapi.so
    }

Note that /user/local may be changed to fit your installation targets.

USING THE PLUGIN
-----------------
While the KDC does not need further configuration, the "kinit" program needs 
some parameters to assure GSS preauth is being executed properly.

1) In may of the scenarios, you need to force kinit to send a GSS preauth 
padata. This is required since otherwise, most of the following options will
not be processed. You can do it by included "-u 200" to the parameter list.

    kinit -u 200
    
Note that 200 is a temporary number assigned to PA_GSS padata. This will change
when this padata becomes a standard.

1) You need to manually specify the OID of the desired GSS mechanism, using the
-X "gss_mech=O.I.D.N.U.M.B.E.R.S.". Otherwise, the default mechanism will be 
selected for you. For example, for selecting GSS-EAP mechanism:

    kinit -u 200 -X "gss_mech=1.3.6.1.4.1.5322.22.1.17"
    
2) The user identity to be used at GSS-API level is taken from the cname 
specified in the kinit call. Note that the plugin will try to obtain credentials
for the specified identity, so you may need to refer to the GSS mechanism 
documentation to know how to configure these credentials. For example, 
    
    kinit alex -u 200 -X "gss_mech=1.3.6.1.4.1.5322.22.1.17" 
    
will try to acquire GSS credentials for identifier "alex", while

    kinit -u 200 -X "gss_mech=1.3.6.1.4.1.5322.22.1.17" 

will use current user as GSS identifier.

3) If you want to let the GSS mechanism to choose a default identifier for you,
just add -X gss_default to the preauth parameters.

    kinit -u 200 -X "gss_mech=1.3.6.1.4.1.5322.22.1.17" -X gss_default

4) If you are in a federated environment, where the client identifier will not
be available in the KDC's database, you must include the  -X gss_federated 
option. This option will force the kinit to use "WELLKNOWN/FEDERRATED" as cname,
while still using the desired identifier at a GSS level.

    kinit alex -u 200 -X "gss_mech=1.3.6.1.4.1.5322.22.1.17" -X gss_federated
    
The previous command line will start a GSS preauthentication process, using the
GSS-EAP mechanism, where "WELLKNOW/FEDERATED" will be used as cname, and "alex" 
will be used at GSS layer.

    kinit -u 200 -X "gss_mech=1.3.6.1.4.1.5322.22.1.17" -X gss_default -X gss_federated
    
The previous command line will start a GSS preauthentication process, using the
GSS-EAP mechanism, where "WELLKNOW/FEDERATED" will be used as cname, and the 
default credentials will be used at GSS layer.

This last form is like to be the most used way to execute GSS preauth, since it
makes a completely mechanism independent call. 



    
    
