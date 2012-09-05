/***************************************************************************
*   Copyright (C) 2012 by                                                 *
*   Alejandro Perez Mendez     alex@um.es                                 *
***************************************************************************/

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

#include <gssapi/gssapi_generic.h>

#include "gssapi_util.h"

/* we need these services since the transport is cleartext */
#define REQUESTED_FLAGS (GSS_C_MUTUAL_FLAG | GSS_C_REPLAY_FLAG | GSS_C_SEQUENCE_FLAG)

/* Definition of the plugin context */
typedef struct {
    char use_default_gss_cred;  /* Use default GSS client credentials ? */
    char federated;             /* User is federated -> is not in the KDC DB */
    gss_OID mech_type;          /* GSS mechanism to be used */
}gssapi_plugin_context_t;

/* Definition of client's per-request context struct */
typedef struct {
    gss_ctx_id_t context;       /* GSS-API contexts related with the request */
    gss_name_t targetname;      /* GSS target name of the KDC */
    gss_cred_id_t client_cred;  /* GSS user name of the client */
} gssapi_req_context_t;

/* This is a normal preauthentication plugin. Thus it returns PA_REAL */
static int
client_get_flags(krb5_context kcontext, krb5_preauthtype pa_type)
{
    return PA_REAL;
}

static krb5_error_code
client_plugin_init(krb5_context context,
                   krb5_clpreauth_moddata *moddata_out)
{
    krb5_error_code rcode = 0;

    gssapi_plugin_context_t *out = k5alloc(sizeof(gssapi_plugin_context_t), &rcode);
    if (out == NULL)
        goto cleanup;

    out->use_default_gss_cred = 0;
    out->federated = 0;
    out->mech_type = GSS_C_NO_OID;

    *moddata_out = (krb5_clpreauth_moddata)out;

cleanup:
    return rcode;
}

static void
client_plugin_fini(krb5_context context, krb5_clpreauth_moddata moddata)
{
    OM_uint32 min_stat = 0, maj_stat = GSS_S_COMPLETE;
    gssapi_plugin_context_t *ctx = (gssapi_plugin_context_t*) moddata;

    maj_stat = gss_release_oid(&min_stat, &ctx->mech_type);
    free (ctx);
}


/* Creates a new GSS request context, with initial values */
static void
client_req_init(krb5_context context, 
                krb5_clpreauth_moddata moddata, 
                krb5_clpreauth_modreq *modreq_out)
{    
    krb5_error_code rcode = 0;
    gssapi_req_context_t *gss_req_context = NULL;
     
    /* alloc a new context */
    gss_req_context = k5alloc(sizeof(gssapi_req_context_t), &rcode);
    if (gss_req_context == NULL)
        return;

    /* establish default values */
    gss_req_context->context = GSS_C_NO_CONTEXT;
    gss_req_context->targetname = GSS_C_NO_NAME;
    gss_req_context->client_cred = GSS_C_NO_CREDENTIAL;
    
    // output
    *modreq_out = (krb5_clpreauth_modreq) gss_req_context;
    
}

/* Deletes the request context */
static void
client_req_fini(krb5_context context, 
                krb5_clpreauth_moddata moddata,
                krb5_clpreauth_modreq modreq)
{    
    OM_uint32 min_stat = 0, maj_stat = GSS_S_COMPLETE;
    gssapi_req_context_t *reqctx = (gssapi_req_context_t*) modreq;
    
    if (reqctx == NULL)
        return;
    
    /* delete the GSS-API security context */
    maj_stat = gss_delete_sec_context(&min_stat, 
                                      &reqctx->context, 
                                      GSS_C_NO_BUFFER);
    if (maj_stat != GSS_S_COMPLETE)
        display_gss_status(maj_stat, min_stat);

    /* delete the target name */
    maj_stat = gss_release_name(&min_stat, &reqctx->targetname);
    if (maj_stat != GSS_S_COMPLETE)
        display_gss_status(maj_stat, min_stat);

    /* delete the client credentials */
    maj_stat = gss_release_cred(&min_stat, &reqctx->client_cred);
    if (maj_stat != GSS_S_COMPLETE)
        display_gss_status(maj_stat, min_stat);

    /* delete the memory struct */
    free(reqctx);        
}

/* receive krb5_get_init_creds_opt information */
static krb5_error_code
client_gic_opt(krb5_context kcontext,
               krb5_clpreauth_moddata moddata,
               krb5_get_init_creds_opt *opt,
               const char *attr,
               const char *value)
{
    gssapi_plugin_context_t* ctx = (gssapi_plugin_context_t*) moddata;
    OM_uint32 maj_stat = GSS_S_COMPLETE, min_stat = 0;
        
    fprintf(stdout, "GSS-PA> client_gic_opt: received '%s' = '%s'\n",
            attr, value);
            
    if (strcmp(attr, "gss_default") == 0){
        ctx->use_default_gss_cred = 1;
    } else if (strcmp(attr, "gss_federated") == 0){
        ctx->federated = 1;
    } else if (strcmp(attr, "gss_mech") == 0){
        gss_buffer_desc temp = GSS_C_EMPTY_BUFFER;
        temp.length = strlen(value);
        temp.value = (void*) value;
        maj_stat = gss_str_to_oid(&min_stat, &temp, &ctx->mech_type);
        if (maj_stat != GSS_S_COMPLETE){
            display_gss_status(maj_stat, min_stat);
            return KRB5KDC_ERR_PREAUTH_FAILED;
        }
    }

    return 0;
}

/* 
 * This function simplifies the use of gss_init_sec_context for the plugin,
 * interfaceing with pa_data, instead of GSS tokens.
 * Outputs a single PA_DATA element
 */
static krb5_error_code 
do_gss_init_sec_context(gss_ctx_id_t * context,    
                        gss_cred_id_t client_cred,
                        gss_name_t target_name,
                        gss_OID mech_type,
                        OM_uint32 req_flags,
                        OM_uint32 *ret_flags,
                        krb5_pa_data *padata_in,  
                        krb5_pa_data **padata_out,
                        krb5_data *encoded_request_body,                         
                        OM_uint32 expected_maj_stat)
{
    OM_uint32 maj_stat = GSS_S_COMPLETE, min_stat = 0;
    gss_buffer_desc input_gss_token = GSS_C_EMPTY_BUFFER;
    gss_buffer_desc output_gss_token = GSS_C_EMPTY_BUFFER;
    struct gss_channel_bindings_struct channel_bindings;
    krb5_error_code rcode = 0;    
    krb5_pa_gss *pa_gss_in = NULL, pa_gss_out;
    krb5_data *temp = 0, temp_static;

    
    /* init krb5_pa_gss */
    pa_gss_out.pagss_token.length = 0;
    pa_gss_out.pagss_token.data = NULL;
    pa_gss_out.pagss_state.ciphertext.length = 0;
    pa_gss_out.pagss_state.ciphertext.data = NULL;
            
    /* set the output PA_DATA to NULL */
    if (padata_out != NULL)
        *padata_out = NULL;

    /* decode the input PA-GSS (if available) */
    if (padata_in != NULL){
        temp_static.data = (char*) padata_in->contents;
        temp_static.length  = padata_in->length;
        rcode = decode_krb5_pa_gss(&temp_static, &pa_gss_in);    
        if (rcode){
            printf("GSS-PA> error decoding PA_GSS\n");
            goto cleanup;    
        }

        /* set upt he input_gss_token (alias) */
        input_gss_token.length = pa_gss_in->pagss_token.length;
        input_gss_token.value = pa_gss_in->pagss_token.data;
    }
    
    
    /* Create channel bindings */
    fill_channel_bindings(encoded_request_body, &channel_bindings);

    /* call gss_init_sec_context */
    maj_stat = gss_init_sec_context(
        &min_stat,              /* min_stat */
        client_cred,            /* initiator_cred_handle */
        context,                /* context_handle */
        target_name,            /* target_name */
        mech_type,              /* requested mech_type */
        req_flags,              /* req_flags */
        0,                      /* time_req 0 = default*/
        &channel_bindings,      /* input_chan_bindings */
        &input_gss_token,       /* input_token */
        NULL,                   /* actual mech type */
        &output_gss_token,      /* output_token */
        ret_flags,              /* ret_flags */
        NULL);                  /* time_rec NULL = we dont care. The TGT will */
                                     
    /* Check whether the status is the expected */
    if (maj_stat != expected_maj_stat) {
        display_gss_status(maj_stat, min_stat);
        rcode = KRB5KDC_ERR_PREAUTH_FAILED;
        goto cleanup;
    }
    
    /* create the out PA_GSS */
    pa_gss_out.pagss_token.data = output_gss_token.value;
    pa_gss_out.pagss_token.length = output_gss_token.length;
    if (pa_gss_in)
        pa_gss_out.pagss_state = pa_gss_in->pagss_state;
            

    /* encode the output PA-GSS if token is provided (PA-GSS-STATE is copied) */
    if (output_gss_token.length != 0 && padata_out != NULL){
        krb5_pa_data *out = NULL;
        rcode = encode_krb5_pa_gss(&pa_gss_out, &temp);
        if (rcode){
            printf("GSS-PA> ERror encoding KRB5_PA_GSS\n");
            goto cleanup;
        }

        out = k5alloc(sizeof(krb5_pa_data), &rcode);
        if (out == NULL)
            goto cleanup;
        
        out->pa_type = KRB5_PADATA_GSS;
        out->contents = (krb5_octet*) temp->data;
        out->length = temp->length;
        temp->data = NULL;
        
        *padata_out = out;
    }
    

cleanup:
    if (pa_gss_in){
        krb5_free_data_contents(NULL, &pa_gss_in->pagss_token);
        krb5_free_data_contents(NULL, &pa_gss_in->pagss_state.ciphertext);
    }
    free(pa_gss_in);
    krb5_free_data_contents(NULL, &pa_gss_out.pagss_token);
    krb5_free_data(NULL, temp);
    return rcode;                                                
}

static krb5_error_code
acquire_client_gss_cred(krb5_context context,
                       krb5_principal cname,
                       gss_OID mech_type,
                       gss_cred_id_t* gss_cred_out)
{
    OM_uint32 maj_stat = GSS_S_COMPLETE, min_stat = 0;
    gss_buffer_desc username = GSS_C_EMPTY_BUFFER;
    gss_name_t gss_username = GSS_C_NO_NAME;
    krb5_error_code rcode = 0;
    gss_cred_id_t out = GSS_C_NO_CREDENTIAL;
    char *username_txt = NULL;
    gss_OID_set desired_mech = GSS_C_NO_OID_SET;
    
    /* initialize output variable */
    *gss_cred_out = GSS_C_NO_CREDENTIAL;
    
    /* create the OID set */
    if (mech_type != GSS_C_NO_OID){
        gss_create_empty_oid_set(&min_stat, &desired_mech);
        gss_add_oid_set_member(&min_stat, mech_type, &desired_mech);
    }
    
    /* read username from the AS_REQ (if any) */
    if (cname){
        rcode = krb5_unparse_name_flags(context, cname, 
                                        KRB5_PRINCIPAL_UNPARSE_NO_REALM, 
                                        &username_txt);    
        if (rcode)
            goto cleanup;    

        printf("GSS-PA> Adquiring GSS credentials for <%s>\n", username_txt);
        
        /* import the client name */
        rcode = fill_gss_buffer_from_data(username_txt, strlen(username_txt),
                                          &username);
        if (rcode)
            goto cleanup;
                                                      
        maj_stat = gss_import_name(&min_stat, &username, GSS_C_NO_OID, 
                                   &gss_username);    
        
        if (maj_stat != GSS_S_COMPLETE) {
            rcode = KRB5KDC_ERR_PREAUTH_FAILED;
            display_gss_status(maj_stat, min_stat);
            goto cleanup;
        }
    }    
    else{
        printf("GSS-PA> Adquiring default GSS credentials\n");    
    }
        
    /* acquire client credentials */
    maj_stat = gss_acquire_cred(
        &min_stat,              /* minor_status */
        gss_username,           /* desired_name */
        GSS_C_INDEFINITE,       /* time_req */
        desired_mech,           /* desired_mechs */
        GSS_C_INITIATE,         /* cred_usage */
        &out,                   /* output_cred_handle */
        NULL,                   /* actual_mechs */
        NULL                    /* time_rec NULL not interested */
    );    
       
    if (maj_stat != GSS_S_COMPLETE) {
        rcode = KRB5KDC_ERR_PREAUTH_FAILED;
        display_gss_status(maj_stat, min_stat);
        goto cleanup;
    }

    *gss_cred_out = out;
    out = GSS_C_NO_CREDENTIAL;

cleanup:
    gss_release_buffer(&min_stat, &username);
    gss_release_name(&min_stat, &gss_username);
    gss_release_cred(&min_stat, &out);
    return rcode;
}                

static krb5_error_code
get_name_from_gss_credential(gss_cred_id_t credential,
                             char **name_out)
{
    OM_uint32 maj_stat = GSS_S_COMPLETE, min_stat = 0;
    krb5_error_code rcode = 0;
    gss_name_t gss_name = GSS_C_NO_NAME;
    gss_buffer_desc gss_name_txt = GSS_C_EMPTY_BUFFER;
    char *out = NULL;
    
    maj_stat = gss_inquire_cred(&min_stat, credential, &gss_name, NULL, 
                                NULL, NULL);                                       
    if (maj_stat != GSS_S_COMPLETE){
        rcode = KRB5KDC_ERR_PREAUTH_FAILED;
        display_gss_status(maj_stat, min_stat);
        goto cleanup;                
    }                                 
    
    maj_stat = gss_display_name(&min_stat, gss_name, &gss_name_txt, NULL);    
    if (maj_stat != GSS_S_COMPLETE){
        rcode = KRB5KDC_ERR_PREAUTH_FAILED;
        display_gss_status(maj_stat, min_stat);
        goto cleanup;                
    }                                 

    out = k5alloc(gss_name_txt.length + 1, &rcode);
    if (out == NULL)
        goto cleanup;    
    
    memcpy(out, gss_name_txt.value, gss_name_txt.length);
    out[gss_name_txt.length] = '\0';
    
    *name_out = out;
    
cleanup:
    gss_release_name(&min_stat, &gss_name);
    gss_release_buffer(&min_stat, &gss_name_txt);
    return rcode;
}                             


/* generates the first PA-GSS of the authentication */
static krb5_error_code
create_first_request(krb5_context context,
                     gssapi_plugin_context_t *pluginctx,
                     gssapi_req_context_t *reqctx,
                     krb5_kdc_req *request,
                     krb5_pa_data *pa_data,
                     krb5_data *encoded_request_body, 
                     krb5_pa_data ***pa_data_out)
{
    OM_uint32 maj_stat = GSS_S_COMPLETE, min_stat = 0;
    krb5_error_code rcode = 0;
    krb5_pa_data **out = NULL;
    gss_buffer_desc targetname_txt = GSS_C_EMPTY_BUFFER;
    char *kdcname = NULL, *cname = NULL, *cname2 = NULL;
    krb5_principal new_principal = NULL;

    /* initilize local output variable */
    out = k5alloc(2 * sizeof(krb5_pa_data *), &rcode);
    if (out == NULL)
        goto cleanup;
    
    out[0] = NULL;
    out[1] = NULL;    
    
    printf("GSS-PA> Start client processing. Creating GSSAPI context\n");
    
    /* acquire client GSS credentials, using the name provided by the client,
       or the default credentials */
    if (pluginctx->use_default_gss_cred)
        rcode = acquire_client_gss_cred(context, NULL, pluginctx->mech_type, &reqctx->client_cred);
    else
        rcode = acquire_client_gss_cred(context, request->client, pluginctx->mech_type,
                                        &reqctx->client_cred);        
    if (rcode)
        goto cleanup;

    /* Update the cname of the AS_REQ in acordance with the provided options */
    if (pluginctx->federated){
        cname = "WELLKNOWN";
        cname2 = "FEDERATED";
    }
    else{
        rcode = get_name_from_gss_credential(reqctx->client_cred, &cname);
        if (rcode)
            goto cleanup;
    }    
               
    /* create a new cname. REALM is not required since we just copy the name */
    rcode = krb5_build_principal(NULL, &new_principal, 0, "", cname, cname2, 
                                 NULL);
    if (rcode)
        goto cleanup;                                        
        
    /* copy the name */
    request->client->data = new_principal->data;
    request->client->length = new_principal->length;
    new_principal->data = NULL;
    new_principal->length = 0;

    printf("GSS-PA> Updated AS_REQ name to <%s/%s>\n", cname, cname2);        

    /* import target name in NT_SERVICE_NAME format */
    rcode = krb5_unparse_name(context, request->server, &kdcname);
    if (rcode)
        goto cleanup;        
        
    rcode = fill_gss_buffer_from_data(kdcname, strlen(kdcname), 
                                      &targetname_txt);
    if (rcode)
        goto cleanup;                                      
                                      
    maj_stat = gss_import_name(&min_stat, &targetname_txt, gss_nt_service_name, 
                               &reqctx->targetname);
    if (maj_stat != GSS_S_COMPLETE) {
        display_gss_status(maj_stat, min_stat);
        rcode = KRB5KDC_ERR_PREAUTH_FAILED;
        goto cleanup;
    }
        
    rcode = do_gss_init_sec_context(&reqctx->context, reqctx->client_cred, 
                                    reqctx->targetname, pluginctx->mech_type,
                                    REQUESTED_FLAGS, NULL, NULL, &out[0],
                                    encoded_request_body, 
                                    GSS_S_CONTINUE_NEEDED); 
    if (rcode)
        goto cleanup;

    print_buffer("GSS-PA> Sending AS_REQ with PA-GSS: ", out[0]->contents, 
                 out[0]->length);       

    /* set the output variable */
    *pa_data_out = out;
    out = NULL;
    
cleanup:
    krb5_free_pa_data(context, out);
    krb5_free_principal(context, new_principal);
    return rcode;
}               
                            

/* Processes the PA-GSS in the last AS_REP message */
static krb5_error_code
process_as_rep(krb5_context context,
               gssapi_plugin_context_t *pluginctx,
               gssapi_req_context_t *reqctx,
               krb5_clpreauth_callbacks cb,
               krb5_clpreauth_rock rock,
               krb5_kdc_req *request,
               krb5_data *encoded_request_body, 
               krb5_pa_data *pa_data)
{
    OM_uint32 maj_stat = GSS_S_COMPLETE, min_stat = 0, ret_flags = 0;
    krb5_error_code rcode = 0;
    gss_buffer_desc prf_in = GSS_C_EMPTY_BUFFER;
    gss_buffer_desc prf_key = GSS_C_EMPTY_BUFFER;  
    krb5_enctype enctype = 0;   
    size_t keybytes = 0, keylen = 0;
    krb5_keyblock as_key; 
    char *gssname = NULL;
    krb5_principal new_principal = NULL;
    
    /* initilize keyblock to NULL */
    as_key.length = 0;
    as_key.contents = NULL;

    print_buffer("GSS-PA> Received PA-GSS in AS_REP: ", 
                 pa_data->contents, 
                 pa_data->length);       

    /* Perform the last call to create context. Expected result is 
       GSS_S_COMPLETE */
    rcode = do_gss_init_sec_context(&reqctx->context, reqctx->client_cred,
                                    reqctx->targetname, pluginctx->mech_type, 
                                    REQUESTED_FLAGS, &ret_flags, pa_data, NULL, 
                                    encoded_request_body, GSS_S_COMPLETE); 
    if (rcode)
        goto cleanup;

    /* check ret_flags */
    printf("GSS-PA> Requested flags=%x. Returned flags=%x. AND=%x\n", 
           REQUESTED_FLAGS, ret_flags, REQUESTED_FLAGS & ret_flags);
    if ( (REQUESTED_FLAGS & ret_flags) != REQUESTED_FLAGS){
        printf("GSS-PA> Some security service cannot be supplied\n");
        rcode = KRB5KDC_ERR_PREAUTH_FAILED;
        goto cleanup;    
    }

    /* the client has been authenticated, derive the as key now */
    enctype = cb->get_etype(context, rock);
    krb5_c_keylengths(0, enctype, &keybytes, &keylen);                
    
    /* reserve enough space for the prf_in */            
    prf_in.value = k5alloc(MAX_PRF_SIZE, &rcode); 
    if (prf_in.value == NULL)
        goto cleanup;    
    
    /* prf.in = 'KRB-GSS' | request->nonce
       Always < MAX_PRF_SIZE bytes. No need to check snprintf output */ 
    snprintf(prf_in.value, MAX_PRF_SIZE, "KRB-GSS%d", request->nonce);            
    prf_in.length = strlen(prf_in.value);

    /* generate the AS_KEY */
    maj_stat = gss_pseudo_random(&min_stat, reqctx->context, GSS_C_PRF_KEY_FULL, 
                                 &prf_in, keylen, &prf_key);
    
    if (maj_stat != GSS_S_COMPLETE){        
        display_gss_status(maj_stat, min_stat);
        rcode = KRB5KDC_ERR_PREAUTH_FAILED;
        goto cleanup;
    }

    /* set the as_key values to the result of gss_pseudo_random and set
       prf_key to empty buffer */
    as_key.length = prf_key.length;
    as_key.enctype = enctype;
    as_key.contents = prf_key.value; 
    prf_key.length = 0;
    prf_key.value = 0;

    rcode = cb->set_as_key(context, rock, &as_key);
    if (rcode)
        goto cleanup;
    
    print_buffer("GSS-PA> Derived AS_KEY: ", as_key.contents, as_key.length);
    
    /* update user's name to the one received via GSS, to avoid errors */
    rcode = get_name_from_gss_credential(reqctx->client_cred, &gssname);
    if (rcode)
        goto cleanup;
               
    /* create a new cname. REALM is not required since we just copy the name */
    rcode = krb5_build_principal(NULL, &new_principal, 0, "", gssname, NULL);
    if (rcode)
        goto cleanup;                                        
        
    /* copy the name */
    request->client->data = new_principal->data;
    request->client->length = new_principal->length;
    new_principal->data = NULL;
    new_principal->length = 0;
    
cleanup:
    gss_release_buffer(&min_stat, &prf_in);
    gss_release_buffer(&min_stat, &prf_key); 
    free(gssname);
    krb5_free_principal(context, new_principal); 
    krb5int_c_free_keyblock_contents(context, &as_key);      
    return rcode;
}

/* Generates PA_DATA for the next AS_REQ message */
static krb5_error_code
client_process(krb5_context context,
               krb5_clpreauth_moddata moddata,
               krb5_clpreauth_modreq modreq,
               krb5_get_init_creds_opt *opt,
               krb5_clpreauth_callbacks cb,
               krb5_clpreauth_rock rock,
               krb5_kdc_req *request,
               krb5_data *encoded_request_body,
               krb5_data *encoded_previous_request,
               krb5_pa_data *pa_data,
               krb5_prompter_fct prompter, 
               void *prompter_data,
               krb5_pa_data ***pa_data_out)
{
    gssapi_plugin_context_t *pluginctx = (gssapi_plugin_context_t*) moddata;
    gssapi_req_context_t *reqctx = (gssapi_req_context_t*) modreq;
    krb5_error_code rcode = 0;
   
    /* if there is not PA_DATA, then this is the first message generation and we 
       initiate the context establishment */
    if (pa_data == NULL || pa_data->length == 0){
        rcode = create_first_request(context, pluginctx, reqctx, request, 
                                     pa_data, encoded_request_body, pa_data_out);
    }
    
    /* If there is PA_DATA, then this is an AS_REP */
    else{
        rcode = process_as_rep(context, pluginctx, reqctx, cb, rock, request, 
                               encoded_request_body, pa_data);
    }
    
    return rcode;
}


static krb5_error_code 
client_try_again(krb5_context context,
                 krb5_clpreauth_moddata moddata,
                 krb5_clpreauth_modreq modreq,
                 krb5_get_init_creds_opt *opt,
                 krb5_clpreauth_callbacks cb,
                 krb5_clpreauth_rock rock,
                 krb5_kdc_req *request,
                 krb5_data *encoded_request_body,
                 krb5_data *encoded_previous_request,
                 krb5_preauthtype pa_type,
                 krb5_error *error,
                 krb5_pa_data **error_padata,
                 krb5_prompter_fct prompter, 
                 void *prompter_data,
                 krb5_pa_data ***pa_data_out)
{                             
    gssapi_plugin_context_t *pluginctx = (gssapi_plugin_context_t*) moddata;
    gssapi_req_context_t *reqctx = (gssapi_req_context_t*) modreq;
    krb5_pa_data *pa_gss = NULL, **out = NULL;
    krb5_error_code rcode = 0;
    
    /* initilize local output variable */
    out = k5alloc(2 * sizeof(krb5_pa_data *), &rcode);
    if (out == NULL)
        goto cleanup;
        
    out[0] = NULL;
    out[1] = NULL;
    
    /* Check the error type. Should not happend, but you never know... */
    if (error->error != KDC_ERR_MORE_PREAUTH_DATA_REQUIRED ){ 
        printf("GSS-PA> Incorrect error type %d\n", error->error);        
        rcode = KRB5KDC_ERR_PREAUTH_FAILED;
        goto cleanup;
    }
    
    /* there should be a PA_DATA within the error data */
    if (error_padata == NULL){
        printf("GSS-PA> No PA_DATA found in error message\n");
        rcode = KRB5KDC_ERR_PREAUTH_FAILED;
        goto cleanup;
    }        
    
    /* get the GSS PA_DATA */
    pa_gss = krb5int_find_pa_data(context, error_padata, KRB5_PADATA_GSS);
    if (pa_gss == NULL){
        printf("GSS-PA> Error: Cannot find PA-GSS\n");                
        rcode = KRB5KDC_ERR_PREAUTH_FAILED;
        goto cleanup;
    }        

    print_buffer("GSS-PA> Received PA-GSS in KRB_ERROR: ", pa_gss->contents, 
                 pa_gss->length);       

    /* call the GSS-API to obtain a token for the next request */
    rcode = do_gss_init_sec_context(&reqctx->context, reqctx->client_cred, 
                                   reqctx->targetname, pluginctx->mech_type, 
                                   REQUESTED_FLAGS, NULL, pa_gss, &out[0], 
                                   encoded_request_body, GSS_S_CONTINUE_NEEDED); 
    if (rcode)
        goto cleanup;

    print_buffer("GSS-PA> Sending PA-GSS in AS_REQ: ", out[0]->contents, 
                 out[0]->length);       

    /* update output variable */
    *pa_data_out = out;
    out = NULL;
        
cleanup:        
    krb5_free_pa_data(context, out);
    return rcode;        
}                                

static krb5_preauthtype supported_client_pa_types[] = {
    KRB5_PADATA_GSS, 0,
};

krb5_error_code
clpreauth_gssapi_initvt(krb5_context context, int maj_ver, int min_ver, 
                        krb5_plugin_vtable vtable);


krb5_error_code
clpreauth_gssapi_initvt(krb5_context context, int maj_ver, int min_ver, 
                        krb5_plugin_vtable vtable)
{
    krb5_clpreauth_vtable vt;
    
    if (maj_ver != 1)
        return KRB5_PLUGIN_VER_NOTSUPP;
    
    vt = (krb5_clpreauth_vtable)vtable;
    vt->name = "gssapi";
    vt->pa_type_list = supported_client_pa_types;
    vt->flags = client_get_flags;
    vt->init = client_plugin_init;    
    vt->fini = client_plugin_fini;    
    vt->request_init = client_req_init;
    vt->request_fini = client_req_fini;
    vt->process = client_process;
    vt->tryagain = client_try_again;
    vt->gic_opts = client_gic_opt;
    return 0;
}
