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

