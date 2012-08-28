#include "autoconf.h"

#ifdef HAVE_ERRNO_H
#include <errno.h>
#endif
#ifdef HAVE_STRING_H
#include <string.h>
#endif

#include <stdio.h>
#include <krb5/krb5.h>
#include <gssapi/gssapi_generic.h>
#include "gssapi_util.h"

#include <arpa/inet.h>

static void 
display_gss_status_1(OM_uint32 code, 
                     int type)
{
    OM_uint32 maj_stat, min_stat;
    gss_buffer_desc msg;
    OM_uint32 msg_ctx;

    msg_ctx = 0;
    while (1) {
        maj_stat = gss_display_status(&min_stat, code, type, GSS_C_NULL_OID, 
                                      &msg_ctx, &msg);
        printf("GSS-PA> GSS-API error: %s\n", (char *) msg.value);
        gss_release_buffer(&min_stat, &msg);

        if (!msg_ctx)
            break;
    }
}

void
display_gss_status(OM_uint32 maj_stat, 
                   OM_uint32 min_stat)
{
    display_gss_status_1(maj_stat, GSS_C_GSS_CODE);
    display_gss_status_1(min_stat, GSS_C_MECH_CODE);
}

void 
print_buffer(char *text, 
             unsigned char* data, 
             int length)
{
    int i;
    fprintf(stderr, "%s\n        [", text);
    for (i=0; i<length - 1; i++){
        if (i && !(i%20) )
            fprintf(stderr, "\n         ");
        fprintf(stderr, "%02X:", data[i]);
    }
    
    if (length > 0)
        fprintf(stderr, "%02X] (%d)\n", data[i], length);
    else
        fprintf(stderr, "](%d)\n", length);
}

void 
print_buffer_txt(char *text, 
                 unsigned char* data, 
                 int length)
{
    int i;
    fprintf(stderr, "%s[", text);
    for (i=0; i<length - 1; i++)
        fprintf(stderr, "%c", data[i]);
    if (length > 0)
        fprintf(stderr, "%c]\n", data[i]);
    else
        fprintf(stderr, "]\n");
}

void 
fill_gss_buffer_from_data(void *data, 
                          unsigned int length, 
                          gss_buffer_t gss_buffer)
{
    gss_buffer->length = length;
    gss_buffer->value = malloc(length);
    memcpy(gss_buffer->value, data, length);
}

void 
fill_pa_data_from_data(void *data, 
                       unsigned int length, 
                       krb5_preauthtype patype, 
                       krb5_pa_data *padata)
{
    padata->pa_type = patype;
    padata->length = length;
    padata->contents = malloc(length);
    memcpy(padata->contents, data, length);         
}

krb5_error_code 
decode_pa_gss(krb5_pa_data* pa_gss,
              gss_buffer_t sec_ctx_token, 
              krb5_data **pa_gss_state_out)
{
    OM_uint32 sec_ctx_token_len = 0, pa_gss_state_len = 0, 
              pa_gss_state_offset = 0, min_stat = 0;          
    krb5_error_code rcode = 0;
    krb5_data *out = NULL;

    if (pa_gss->length < 5){
        rcode = KRB5KDC_ERR_PREAUTH_FAILED;
        printf("GSS-PA> Invalid PA-GSS length %d\n", pa_gss->length);
        goto cleanup;
    }
    
    memcpy(&sec_ctx_token_len, pa_gss->contents, 4);
    sec_ctx_token_len = ntohl(sec_ctx_token_len);

    sec_ctx_token->length = sec_ctx_token_len;
    sec_ctx_token->value = malloc(sec_ctx_token_len);
    memcpy(sec_ctx_token->value, &pa_gss->contents[4], sec_ctx_token_len);
    
    pa_gss_state_offset = 4 + sec_ctx_token_len;
    
    /* check for a state */
    if (pa_gss->length > pa_gss_state_offset){
        if (pa_gss->length < pa_gss_state_offset + 5){
            rcode = KRB5KDC_ERR_PREAUTH_FAILED;
            printf("GSS-PA> Invalid PA-GSS-STATE length %d\n", pa_gss->length);
            goto cleanup;
        }
                  
        memcpy(&pa_gss_state_len, &pa_gss->contents[pa_gss_state_offset], 4);
        pa_gss_state_len = ntohl(pa_gss_state_len);

        out = malloc(sizeof(krb5_data));
        
        out->length = pa_gss_state_len;
        out->data = malloc(pa_gss_state_len);
        memcpy(out->data, &pa_gss->contents[pa_gss_state_offset + 4], 
               pa_gss_state_len);

    }

    *pa_gss_state_out = out;               
    return 0;    
    
cleanup:
    gss_release_buffer(&min_stat, sec_ctx_token);            
    krb5_free_data(NULL, out);            
    return rcode;
}

/* XXX USE ASN1 */
krb5_error_code 
encode_pa_gss(gss_buffer_t sec_ctx_token, 
              krb5_data* pa_gss_state, 
              krb5_pa_data** pa_gss_out)
{
    OM_uint32 sec_ctx_token_len = 0, pa_gss_state_len = 0, pa_gss_state_offset = 0;
    krb5_pa_data* out = malloc(sizeof(krb5_pa_data));
    
    out->pa_type = KRB5_PADATA_GSS;
    
    pa_gss_state_len = (pa_gss_state == NULL ? 0 : pa_gss_state->length);
        
    /* reserve the maximum length */
    out->contents = malloc(4 + sec_ctx_token->length + 4 + pa_gss_state_len);        
    out->length = 4 + sec_ctx_token->length;
    
    sec_ctx_token_len = htonl(sec_ctx_token->length);
    memcpy(out->contents, &sec_ctx_token_len, 4);
    memcpy(&out->contents[4], sec_ctx_token->value, sec_ctx_token->length);

    if (pa_gss_state != NULL){    
        out->length += 4 + pa_gss_state->length;
        pa_gss_state_offset = 4 + sec_ctx_token->length;
        pa_gss_state_len = htonl(pa_gss_state->length);
        memcpy(&out->contents[pa_gss_state_offset], &pa_gss_state_len, 4);
        memcpy(&out->contents[pa_gss_state_offset + 4], pa_gss_state->data, 
               pa_gss_state->length);
    }
    
    *pa_gss_out = out;
    
    /* exit without error */
    return 0;    
}

void
fill_channel_bindings(krb5_data* encoded_request_body, 
                      gss_channel_bindings_t channel_bindings)
{
    channel_bindings->initiator_addrtype = GSS_C_AF_UNSPEC;
    channel_bindings->initiator_address.length = 0;
    channel_bindings->initiator_address.value = NULL;
    channel_bindings->acceptor_addrtype = GSS_C_AF_UNSPEC;
    channel_bindings->acceptor_address.length = 0;
    channel_bindings->acceptor_address.value = NULL;
    channel_bindings->application_data.length = encoded_request_body->length;
    channel_bindings->application_data.value = encoded_request_body->data;
}

