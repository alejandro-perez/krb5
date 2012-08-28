/*
 * This is a GSSAPI pluging for the KDC project (Client side)
 */

#include "autoconf.h"

#ifdef HAVE_ERRNO_H
#include <errno.h>
#endif
#ifdef HAVE_STRING_H
#include <string.h>
#endif

#include <arpa/inet.h>
#include <stdio.h>

#include <k5-int.h>
#include <krb5/krb5.h>
#include <krb5/preauth_plugin.h>
#include <gssapi_util.h>

#include "kdc_util.h"

/* Definition of server's per-request context struct */
typedef struct gsspreauth_req_context_t {
    gss_ctx_id_t context;       /* GSS-API contexts related with the request */
    krb5_pa_data** pa_rep;      /* PA_DATA to be included in AS_REP message */
} gssapi_req_context_t;


/* Creates a new initialized request context */
static gssapi_req_context_t* 
make_req_context()
{
    gssapi_req_context_t* ctx = malloc(sizeof(gssapi_req_context_t));    

    ctx->context = GSS_C_NO_CONTEXT;
    ctx->pa_rep = NULL;

    return ctx;
}

/* Frees request context */
static void 
free_modreq(krb5_context context,
            krb5_kdcpreauth_moddata moddata,
            krb5_kdcpreauth_modreq modreq)
{
    OM_uint32 min_stat=0, maj_stat=0;
    gssapi_req_context_t* reqctx = (gssapi_req_context_t*) modreq;

    if (reqctx == NULL)
        return;
              
    /* delete the PA_DATA */        
    krb5_free_pa_data(context, reqctx->pa_rep);    

    /* GSS context can be deleted */
    maj_stat = gss_delete_sec_context(&min_stat, &reqctx->context, 
               GSS_C_NO_BUFFER);

    free(reqctx);       
}                                       

/* get KDC key */
static krb5_error_code
get_krbtgt_key(krb5_context kcontext,
               krb5_keyblock *keyblock, 
               krb5_kvno* kvno_out)
{
    krb5_error_code rcode = 0;
    char *realm = NULL;
    krb5_db_entry *kdc_db_entry = NULL;
    krb5_key_data *kdc_keydata = NULL; 
    krb5_principal kdc = NULL;
    
    /* get the default realm */
    rcode = krb5_get_default_realm(kcontext, &realm);
    if (rcode)
        goto cleanup;

    /* get the DB entry for krbtgt/REALM@REALM */
    rcode = krb5_build_principal(kcontext, &kdc, strlen(realm), realm,
                                 "krbtgt", realm, NULL);
    if (rcode)
        goto cleanup;                                 

    /* Find the server key */
    rcode = krb5_db_get_principal(kcontext, kdc, 0, &kdc_db_entry);
    if (rcode){                                         
        printf("GSS-PA> Cannot find principal krbtgt/%s@%s\n", realm, realm);
        goto cleanup;
    }
  
    /* get keydata. ignore keytype, saltype and get the highest kvno */
    rcode = krb5_dbe_find_enctype(kcontext, kdc_db_entry, -1,-1, 0, 
                                  &kdc_keydata);
    if (rcode){                                         
        printf("GSS-PA> Cannot find the krbtgt key %d\n", rcode);
        goto cleanup;
    }

    /* obtain the actual key */
    rcode = krb5_dbe_decrypt_key_data(kcontext, NULL, kdc_keydata, keyblock,    
                                      NULL);
    if (rcode){                                      
        printf("GSS-PA> Cannot decrypt krbtgt key %d\n", rcode);
        goto cleanup;
    }

    /* update KVNO */
    *kvno_out = kdc_keydata->key_data_kvno;

cleanup:
    krb5_db_free_principal(kcontext, kdc_db_entry);
    krb5_dbe_free_key_data_contents(kcontext, kdc_keydata);
    free(realm);
    return rcode;   
}               

/* decodes an encrypted PA_GSS_STATE */
static krb5_error_code
decode_pa_gss_state(krb5_context kcontext,
                    krb5_kdc_req *request,
                    krb5_data *pa_gss_state,
                    krb5_timestamp *timestamp_out,
                    gss_buffer_t exported_sec_ctx_token)
{
    krb5_error_code rcode = 0;
    krb5_timestamp ts = 0;
    krb5_kvno kvno = 0;
    krb5_enc_data *encrypted_data = NULL;
    krb5_keyblock kdc_keyblock = {0, 0, 0, NULL};
    krb5_data decrypted_data = {0, 0, NULL};
    
    /* obtain KDC key and KVNO */
    rcode = get_krbtgt_key(kcontext, &kdc_keyblock, &kvno);
    if (rcode){
        printf("GSS-PA> Could not get key\n");
        goto cleanup;
    }

    /* decode data */
    rcode = decode_krb5_enc_data(pa_gss_state, &encrypted_data);
    if (rcode){
        printf("GSS-PA> Cannot decode data %d\n", rcode);
        goto cleanup;
    }
    
    /* decrypt data */
    decrypted_data.data = malloc(encrypted_data->ciphertext.length);
    decrypted_data.length = encrypted_data->ciphertext.length;
    rcode = krb5_c_decrypt(kcontext, &kdc_keyblock, PA_GSS_KEYUSAGE, NULL, 
                           encrypted_data, &decrypted_data);    
    if (rcode){
        printf("GSS-PA> Cannot decrypt data %d\n", rcode);
        goto cleanup;
    }
    
    
    memcpy(&ts, decrypted_data.data, 4);
    ts = ntohl(ts);
    
    /* build the GSS_BUFFER with the decrypted data */
    fill_gss_buffer_from_data(&decrypted_data.data[4], decrypted_data.length - 4, 
                              exported_sec_ctx_token);
    
    *timestamp_out = ts;
    return 0;       
cleanup:
    krb5_free_keyblock_contents(kcontext, &kdc_keyblock);   
    krb5_free_data_contents(kcontext, &decrypted_data); 
    krb5_free_enc_data(kcontext, encrypted_data);
   return rcode;

}                    


/* tries to import a received state (if present and valid) */
static void 
process_pa_gss_state(krb5_context kcontext,
                    krb5_kdc_req *request,
                    krb5_data *pa_gss_state,
                    gss_ctx_id_t *context_out)
{
    OM_uint32 maj_stat = 0, min_stat = 0;
    krb5_error_code rcode = 0;      
    krb5_timestamp timestamp = 0, ts_current = 0;
    gss_buffer_desc exported_sec_ctx_token = GSS_C_EMPTY_BUFFER;
    
    if (pa_gss_state == NULL){
        printf("GSS-PA> PA-GSS-STATE not found. Assuming new context\n");    
        return;
    }
    
    /* decode PA_GSS_STATE */
    rcode = decode_pa_gss_state(kcontext, request, pa_gss_state, &timestamp, 
                                &exported_sec_ctx_token);
    if (rcode){
        printf("GSS-PA> Could not decode PA-GSS-STATE\n");
        goto cleanup;
    }

    /* get current timestamp */
    rcode = krb5_timeofday(kcontext, &ts_current);
    if (rcode){
        printf("GSS-PA> Could not get current timestamp\n");
        goto cleanup;            
    }
        
    /* check timestamp is not older than 1 second */
    if (ts_current - timestamp > 1){
        printf("GSS-PA> Timestamp too old. Rejecting state. CURRENT = %d, "
                "STATE_TS = %d\n", ts_current, timestamp);
        goto cleanup;            
    }
    
    /* import state */
    maj_stat = gss_import_sec_context(&min_stat, &exported_sec_ctx_token, 
                                      context_out);
    if (maj_stat != GSS_S_COMPLETE){
        printf("GSS-PA> Invalid PA-GSS-STATE found. Assuming new context\n");
        goto cleanup;
    }

    printf("GSS-PA> Valid PA-GSS-STATE found! Updating context value\n");

cleanup:
    gss_release_buffer(&min_stat, &exported_sec_ctx_token);
}

/* generate a cookie to be sent to the client */
static krb5_error_code 
encode_pa_gss_state(krb5_context kcontext,
                    krb5_timestamp timestamp,
                    gss_buffer_t exported_sec_ctx_token, 
                    krb5_data **pa_gss_state_out)
{
    krb5_error_code rcode = 0;
    krb5_kvno kvno = 0;
    krb5_data plaintext = {0, 0, NULL};
    krb5_keyblock kdc_keyblock = {0, 0, 0, NULL};
    krb5_enc_data encrypted_data = {0, 0, 0, {0, 0, NULL}};
    krb5_data *encoded_data = NULL;    
    
    /* prepare plainstate */
    plaintext.length = exported_sec_ctx_token->length + 4;
    plaintext.data = malloc(plaintext.length);
    
    /* copy timestamp */
    timestamp = htonl(timestamp);
    memcpy(plaintext.data, &timestamp, 4);

    /* copy exported_sec_ctx_token */
    memcpy(&plaintext.data[4], exported_sec_ctx_token->value, 
           exported_sec_ctx_token->length);;

    /* get KDC key and KVNO */
    rcode = get_krbtgt_key(kcontext, &kdc_keyblock, &kvno);
    if (rcode){
        printf("GSS-PA> Could not get key\n");
        goto cleanup;
    }
                                               
    /* encrypt data */
    rcode = krb5_encrypt_helper(kcontext, &kdc_keyblock, PA_GSS_KEYUSAGE, 
                                &plaintext, &encrypted_data);    
    if (rcode){
        printf("GSS-PA> Cannot encrypt data %d\n", rcode);
        goto cleanup;
    }
    
    /* update KVNO */
    encrypted_data.kvno = kvno;    
    
    /* encode the data */
    rcode = encode_krb5_enc_data(&encrypted_data, &encoded_data);
    if (rcode){
        printf("GSS-PA> Cannot encode data %d\n", rcode);
        goto cleanup;
    }
    
    *pa_gss_state_out = encoded_data;
    
cleanup:
    krb5_free_keyblock_contents(kcontext, &kdc_keyblock);    
    krb5_free_data_contents(kcontext, &encrypted_data.ciphertext);
    krb5_free_data_contents(kcontext, &plaintext);
    return rcode;
}

/* generate a cookie to be sent to the client */
static krb5_error_code 
generate_pa_gss_state(krb5_context kcontext,
                      gss_ctx_id_t *gss_context, 
                      krb5_data **pa_gss_state_out)
{
    OM_uint32 maj_stat = 0, min_stat = 0;  
    krb5_error_code rcode = 0;
    krb5_timestamp ts_current = 0;
    gss_buffer_desc exported_sec_ctx_token = GSS_C_EMPTY_BUFFER;

    
    /* obtain context */
    maj_stat = gss_export_sec_context(&min_stat, gss_context, 
                                      &exported_sec_ctx_token);
    if (maj_stat != GSS_S_COMPLETE){
        rcode = KRB5KDC_ERR_PREAUTH_FAILED;
        display_gss_status(maj_stat, min_stat);
        printf("GSS-PA> Could not export SEC context\n");
        goto cleanup;
    }


    /* get current timestamp */
    rcode = krb5_timeofday(kcontext, &ts_current);
    if (rcode){
        printf("GSS-PA> Could not get current timestamp\n");
        goto cleanup;            
    }

    rcode = encode_pa_gss_state(kcontext, ts_current, &exported_sec_ctx_token, 
                                pa_gss_state_out);
    if (rcode){
        printf("GSS-PA> Could not encode PA-GSS-STATE\n");
        goto cleanup;
    }

cleanup:
    gss_release_buffer(&min_stat, &exported_sec_ctx_token);
    return rcode;
}

/* Obtain and return any preauthentication data (which is destined for the
 * client) which matches type data->pa_type. In this case this is sent as an 
 * empty PA_DATA
 */
static void
server_get_edata(krb5_context context, 
                 krb5_kdc_req *request,
                 krb5_kdcpreauth_callbacks cb,
                 krb5_kdcpreauth_rock rock,
                 krb5_kdcpreauth_moddata moddata,
                 krb5_preauthtype pa_type,
                 krb5_kdcpreauth_edata_respond_fn respond,
                 void *arg)
{
    /* include empty hint */
    (*respond)(arg, 0, NULL);    
}


/* outputs a single attribute. taken from gss-server sample app */
static void
dump_attribute(OM_uint32 *minor,
               gss_name_t name,
               gss_buffer_t attribute,
               int noisy)
{
    OM_uint32 major, tmp;
    gss_buffer_desc value;
    gss_buffer_desc display_value;
    int authenticated = 0;
    int complete = 0;
    int more = -1;

    while (more != 0) {
        value.value = NULL;
        display_value.value = NULL;

        major = gss_get_name_attribute(minor, name, attribute, &authenticated,
                                       &complete, &value, &display_value,
                                       &more);

        /* if cannot get the attribute, just silently omit it */
        if (GSS_ERROR(major))
            break;


        print_buffer_txt("GSS-PA> Attribute: ", attribute->value, 
                         attribute->length);
        if (noisy){
            print_buffer_txt("GSS-PA> Value (txt): ", display_value.value, 
                             display_value.length);
            print_buffer("GSS-PA> Value: ", value.value, value.length);
            printf("GSS-PA> Authenticated: %d, Complete: %d\n", authenticated, 
                   complete);
        }
        
        gss_release_buffer(&tmp, &value);
        gss_release_buffer(&tmp, &display_value);
    }
}

/* outputs all the attributes of a name. taken from gss-server sample app */
static OM_uint32
enumerate_attributes(OM_uint32 *minor,
                     gss_name_t name,
                     int noisy)
{
    OM_uint32 major, tmp;
    int name_is_MN;
    gss_OID mech = GSS_C_NO_OID;
    gss_buffer_set_t attrs = GSS_C_NO_BUFFER_SET;
    unsigned int i;

    major = gss_inquire_name(minor, name, &name_is_MN, &mech, &attrs);
    if (GSS_ERROR(major)) {
        display_gss_status(major, *minor);
        return major;
    }

    if (attrs != GSS_C_NO_BUFFER_SET) {
        for (i = 0; i < attrs->count; i++)
            dump_attribute(minor, name, &attrs->elements[i], noisy);
    }

    gss_release_oid(&tmp, &mech);
    gss_release_buffer_set(&tmp, &attrs);

    return major;
}

/* processses the client name received into the AS_REQ and the one obtained
   throught the GSS-API. */
static krb5_error_code
process_client_name(krb5_enc_tkt_part *enc_tkt_reply,
                    gss_name_t gss_clientname)
{
    krb5_error_code rcode = 0;
    OM_uint32 maj_stat = 0, min_stat = 0;
    char *gss_cname = NULL, *as_req_cname = NULL;
    gss_buffer_desc gss_clientname_txt = GSS_C_EMPTY_BUFFER;

    /* get the user name from the AS_REQ */
    rcode = krb5_unparse_name_flags(NULL, enc_tkt_reply->client, 
                                    KRB5_PRINCIPAL_UNPARSE_NO_REALM, 
                                    &as_req_cname);
    if (rcode)
        goto cleanup;
                                            
    printf("GSS-PA> Client name from AS_REQ is [%s]\n", as_req_cname);

    /* get text-form GSS client name */
    maj_stat = gss_display_name(&min_stat, gss_clientname, &gss_clientname_txt, 
                                NULL);                        
    if (maj_stat != GSS_S_COMPLETE){
        display_gss_status(maj_stat, min_stat);
        rcode = KRB5KDC_ERR_PREAUTH_FAILED;
        goto cleanup;
    }
    
    /* create a new char* with the text_gss_clientname to be used */
    gss_cname = malloc(gss_clientname_txt.length + 1);
    memcpy(gss_cname, gss_clientname_txt.value, gss_clientname_txt.length);
    gss_cname[gss_clientname_txt.length] = '\0';
          
    printf("GSS-PA> Client name from GSS-API: [%s]\n", gss_cname);
    
    /* if cname was WELLKNOW/FEDERATED, then update the name with the one
       supplied by the GSS-API */
    if (strcmp(as_req_cname, "WELLKNOWN/FEDERATED") == 0){            
        krb5_principal new_principal = NULL;
    
        /* build a new kerberos principal using the clientname from GSS. 
            REALM is not required since we will copy just the name  */
        rcode = krb5_build_principal(NULL, &new_principal, 0, "", gss_cname, 
                                     NULL);  
        if (rcode)
            goto cleanup;                             

        /* update the TGT cname */        
        enc_tkt_reply->client->data = new_principal->data;
        enc_tkt_reply->client->length = new_principal->length;
        new_principal->data = NULL;
        new_principal->length = 0;
        krb5_free_principal(NULL, new_principal);

        printf("GSS-PA> Updating cname in the ticket to the one from GSS\n");
    }

    /* check that supplied name is consistent with expected NAME */
    else if (strcmp(as_req_cname, gss_cname) != 0){
        printf("GSS-PA> Name mismatch. User cannot be authenticated. \n");
        rcode = KRB5KDC_ERR_PREAUTH_FAILED;
        goto cleanup;        
    }
        
cleanup:
    free(as_req_cname);
    free(gss_cname);
    gss_release_buffer(&min_stat, &gss_clientname_txt);    
    return rcode;        
}


/* processes a GSS_S_CONTINUE_NEEDED result */
static krb5_error_code
process_gss_continue_needed(krb5_context kcontext,
                            gss_ctx_id_t *gss_ctx, 
                            gss_buffer_t output_gss_token,
                            krb5_pa_data ***e_data_out)
{    
    krb5_error_code rcode = 0;
    krb5_pa_data **out = NULL;
    krb5_data *new_gss_state = NULL;

    /* create the PA-GSS to be included in either KRB_ERROR or AS_REP message */
    out = malloc(2 * sizeof(krb5_pa_data*));
    out[0] = NULL;
    out[1] = NULL;

    /* generate the new PA-GSS-STATE */
    rcode = generate_pa_gss_state(kcontext, gss_ctx, &new_gss_state);
    if (rcode)
        goto cleanup;
    
    rcode = encode_pa_gss(output_gss_token, new_gss_state, &out[0]);
    if (rcode)
        goto cleanup;

    print_buffer("GSS-PA> Sent KRB_ERROR with PA-GSS: ", out[0]->contents, 
                 out[0]->length);      
    
    *e_data_out = out;
    out = NULL;
    rcode = KRB5KDC_ERR_MORE_PREAUTH_DATA_REQUIRED;

cleanup:
    krb5_free_pa_data(NULL, out);
    krb5_free_data(kcontext, new_gss_state);
    return rcode;
}

/* processes a GSS_S_COMPLETE result */
static krb5_error_code
process_gss_complete(gss_ctx_id_t *gss_ctx,
                     OM_uint32 ret_flags,    
                     OM_uint32 time_rec,    
                     gss_buffer_t output_gss_token,
                     gss_name_t gss_clientname,
                     krb5_enc_tkt_part* enc_tkt_reply,
                     gssapi_req_context_t *reqctx,
                     krb5_authdata ***authdata_out)
{    
    gss_buffer_desc gss_exported_name = GSS_C_EMPTY_BUFFER;
    krb5_error_code rcode = 0;
    OM_uint32 maj_stat = 0, min_stat = 0;  
    krb5_authdata **auth_list = NULL;      
    OM_uint32 expected_flags = GSS_C_MUTUAL_FLAG | GSS_C_REPLAY_FLAG | 
                               GSS_C_SEQUENCE_FLAG | GSS_C_TRANS_FLAG;

    /* check flags */
    printf("GSS-PA> Expected flags=%x. Returned flags=%x. AND=%x\n", 
           expected_flags, ret_flags, expected_flags & ret_flags);    
    if ( !(ret_flags & expected_flags)){
        printf("GSS-PA> Some security service cannot be supplied\n");
        rcode = KRB5KDC_ERR_PREAUTH_FAILED;
        goto cleanup;
    }

    /* processes the client name */
    rcode = process_client_name(enc_tkt_reply, gss_clientname);
    if (rcode)
        goto cleanup;

    /* include the PA-GSS in the request context to be included in the AS_REP */
    reqctx->pa_rep = malloc(2 * sizeof(krb5_pa_data*));
    reqctx->pa_rep[0] = NULL;
    reqctx->pa_rep[1] = NULL;
    
    rcode = encode_pa_gss(output_gss_token, NULL, &reqctx->pa_rep[0]);
    if (rcode)
        goto cleanup;

    print_buffer("GSS-PA> Sent AS_REP with PA-GSS: ",
                 reqctx->pa_rep[0]->contents, reqctx->pa_rep[0]->length);      
    
    /* store the GSS context */
    reqctx->context = *gss_ctx;
    *gss_ctx = GSS_C_NO_CONTEXT;

    /* export the composite name and introduce it as authorization element */
    maj_stat = gss_export_name_composite(&min_stat, gss_clientname, 
                                         &gss_exported_name);
    if (maj_stat == GSS_S_COMPLETE){
        /* Create the authorization data list */
        auth_list = malloc(2 * sizeof(krb5_authdata *));
        auth_list[0] = malloc(sizeof(krb5_authdata));
        auth_list[0]->ad_type = (krb5_authdatatype) AUTHZ_GSS_ATTRIBUTE;
        auth_list[0]->length = gss_exported_name.length;
        auth_list[0]->contents = malloc(gss_exported_name.length);
        memcpy(auth_list[0]->contents, gss_exported_name.value, 
               gss_exported_name.length);
        auth_list[1] = NULL;     
    }
    
    *authdata_out = auth_list;
    auth_list = NULL;
    
    /* mark the TKT as SUCCESS */
    enc_tkt_reply->flags |= TKT_FLG_PRE_AUTH;    
    
    /* manage time */
    if (time_rec != GSS_C_INDEFINITE){
        enc_tkt_reply->times.endtime = enc_tkt_reply->times.authtime + time_rec;
        enc_tkt_reply->times.renew_till = enc_tkt_reply->times.endtime;
    }
        
    /* XXX DEBUG to be deleted */
    maj_stat = enumerate_attributes(&min_stat, gss_clientname, 0);
    if (GSS_ERROR(maj_stat)) {
        display_gss_status(maj_stat, min_stat);
        rcode = KRB5KDC_ERR_PREAUTH_FAILED;
        goto cleanup;
    }

cleanup:
    gss_release_buffer(&min_stat, &gss_exported_name);
    krb5_free_authdata(NULL, auth_list);
    return rcode;
}


/* Verify a request from a client. */
static void
server_verify(krb5_context context,
              krb5_data *req_pkt, 
              krb5_kdc_req *request,
              krb5_enc_tkt_part *enc_tkt_reply,
              krb5_pa_data *data,
              krb5_kdcpreauth_callbacks cb,
              krb5_kdcpreauth_rock rock,
              krb5_kdcpreauth_moddata moddata,
              krb5_kdcpreauth_verify_respond_fn respond,
              void *arg)
{
    OM_uint32 maj_stat = 0, min_stat = 0, ret_flags = 0, time_rec = 0;
    krb5_error_code rcode = 0;
    gssapi_req_context_t *reqctx = NULL;
    gss_buffer_desc output_gss_token = GSS_C_EMPTY_BUFFER;
    gss_buffer_desc input_gss_token = GSS_C_EMPTY_BUFFER;
    gss_name_t gss_clientname = NULL;
    krb5_data *pa_gss_state = NULL;
    gss_ctx_id_t gss_ctx = GSS_C_NO_CONTEXT;
    krb5_pa_data **e_data = NULL;
    krb5_authdata **auth_list = NULL;
    struct gss_channel_bindings_struct channel_bindings;
                   
    print_buffer("GSS-PA> Received PA-GSS: ", data->contents, data->length);

    /* decode the PA-GSS */
    rcode = decode_pa_gss(data, &input_gss_token, &pa_gss_state);
    if (rcode)
        goto cleanup;
    
    /* try to import the received PA-GSS-STATE (if any) */
    process_pa_gss_state(context, request, pa_gss_state, &gss_ctx);
         
    /* prepare channel bindings struct */
    fill_channel_bindings(cb->request_body(context, rock), &channel_bindings);

    /* Call gss_accept_sec_context */ 
    maj_stat = gss_accept_sec_context(
        &min_stat,              /* min_stat */
        &gss_ctx,               /* context */
        GSS_C_NO_CREDENTIAL,    /* acceptor_cred_handle */
        &input_gss_token,       /* input_token_buffer */
        &channel_bindings,      /* input_channel_bindings */
        &gss_clientname,        /* src_name */
        NULL,                   /* mech_type. Not interested */ 
        &output_gss_token,      /* output_token */
        &ret_flags,             /* ret_flags */
        &time_rec,              /* time_rec */
        NULL);                  /* delegated_cred_handle. Not interested */

    /* Check whether the status is either COMPLETE or CONTINUE_NEEDED */
    if (maj_stat != GSS_S_COMPLETE && maj_stat != GSS_S_CONTINUE_NEEDED) {
        display_gss_status(maj_stat, min_stat);
        rcode = KRB5KDC_ERR_PREAUTH_FAILED;
        goto cleanup;
    }
    
    /* If we need to perform more roundtrips */
    if (maj_stat == GSS_S_CONTINUE_NEEDED)
        rcode = process_gss_continue_needed(context, &gss_ctx,
                                            &output_gss_token, &e_data);
    
    /* If we have finalized, then send an AS_REP with the final PA_DATA */
    else if (maj_stat == GSS_S_COMPLETE) {
        reqctx = make_req_context();
        rcode = process_gss_complete(&gss_ctx, ret_flags, time_rec, 
                                     &output_gss_token, gss_clientname,
                                     enc_tkt_reply, reqctx, &auth_list);                                     
    }
    
cleanup:
    gss_release_name(&min_stat, &gss_clientname);    
    gss_release_buffer(&min_stat, &input_gss_token);    
    krb5_free_data(context, pa_gss_state);    
    gss_release_buffer(&min_stat, &output_gss_token);           
    (*respond)(arg, rcode, (krb5_kdcpreauth_modreq) reqctx, e_data, auth_list);            
}

/* Create the AS_REP for the client */
static krb5_error_code
server_return(krb5_context context,
              krb5_pa_data *padata,
              krb5_data *req_pkt,
              krb5_kdc_req *request,
              krb5_kdc_rep *reply,
              krb5_keyblock *encrypting_key,
              krb5_pa_data **send_pa_out,
              krb5_kdcpreauth_callbacks cb,
              krb5_kdcpreauth_rock rock,
              krb5_kdcpreauth_moddata moddata,
              krb5_kdcpreauth_modreq modreq)
{
    gssapi_req_context_t *reqctx = (gssapi_req_context_t*) modreq;
    gss_buffer_desc prf_in = GSS_C_EMPTY_BUFFER;
    gss_buffer_desc prf_key = GSS_C_EMPTY_BUFFER;                
    OM_uint32 maj_stat = 0, min_stat = 0;
    krb5_error_code rcode = 0;
    
    /* just to be safe */
    if (modreq == NULL)
        return 0;   
    
    /* prf.in = 'KRB-GSS' | request->nonce
       Always < 200 bytes. No need to check snprintf output */ 
    prf_in.value = malloc(200);
    snprintf(prf_in.value, 200, "KRB-GSS%d", request->nonce);
    prf_in.length = strlen(prf_in.value);      
   
    /* calculate the PRF */
    maj_stat = gss_pseudo_random(&min_stat, reqctx->context, GSS_C_PRF_KEY_FULL, 
                                 &prf_in, encrypting_key->length, &prf_key);

    if (maj_stat != GSS_S_COMPLETE){
        display_gss_status(maj_stat, min_stat);
        rcode = KRB5KDC_ERR_PREAUTH_FAILED;
        goto cleanup;
    }                                 

    print_buffer("GSS-PA> Derived reply key: ", prf_key.value, prf_key.length);

    /* repace the user key */
    memcpy(encrypting_key->contents, prf_key.value, prf_key.length);
    
    /* include the KRB5_PADATA_GSS in the list of the AS_REP */
    *send_pa_out = reqctx->pa_rep[0];
    reqctx->pa_rep[0] = NULL;

cleanup:
    gss_release_buffer(&min_stat, &prf_in);
    gss_release_buffer(&min_stat, &prf_key);
                  
    return rcode;
}

static int
server_get_flags(krb5_context kcontext, krb5_preauthtype pa_type)
{
    return PA_SUFFICIENT | PA_REPLACES_KEY;
}

static krb5_preauthtype supported_server_pa_types[] = {
    KRB5_PADATA_GSS, 
    0
};

krb5_error_code
kdcpreauth_gssapi_initvt(krb5_context context, int maj_ver,
                     int min_ver, krb5_plugin_vtable vtable);

krb5_error_code
kdcpreauth_gssapi_initvt(krb5_context context, int maj_ver,
                     int min_ver, krb5_plugin_vtable vtable)
{
    krb5_kdcpreauth_vtable vt;

    if (maj_ver != 1)
        return KRB5_PLUGIN_VER_NOTSUPP;
    
    vt = (krb5_kdcpreauth_vtable)vtable;
    vt->name = "gssapi";
    vt->pa_type_list = supported_server_pa_types;
    vt->flags = server_get_flags;
    vt->edata = server_get_edata;
    vt->verify = server_verify;
    vt->return_padata = server_return;
    vt->free_modreq = free_modreq;
    return 0;
}
