#include "autoconf.h"

#ifdef HAVE_ERRNO_H
#include <errno.h>
#endif
#ifdef HAVE_STRING_H
#include <string.h>
#endif

#include <krb5/krb5.h>
#include <gssapi/gssapi_ext.h>

/* These are not standardized values. They're defined here only to make it
   easier its modification within this module. */
#define KRB5_PADATA_GSS         200
#define AUTHZ_GSS_ATTRIBUTE     200
#define PA_GSS_KEYUSAGE         512

/* prints a data array in hex format, prepending the indicated text string */
void print_buffer(char *text, unsigned char* data, int length);

/* prints a data array in text format, prepending the indicated text string */
void print_buffer_txt(char *text, unsigned char* data, int length);

/* fills a gss buffer with a copy of the data provided */
void fill_gss_buffer_from_data(void *data, unsigned int length, 
                               gss_buffer_t gss_buffer);

/* fills a krb5_pa_data with a copy of the data provided */
void fill_pa_data_from_data(void *data, unsigned int length, 
                            krb5_preauthtype patype, krb5_pa_data *padata);

/* prints the GSS error in a textual form */
void display_gss_status(OM_uint32 maj_stat, OM_uint32 min_stat);

/* decodes a PA-GSS into a GSS-TOKEN and a PA-GSS-STATE */
krb5_error_code decode_pa_gss(krb5_pa_data* pa_gss, gss_buffer_t sec_ctx_token, 
                              krb5_data **pa_gss_state_out);
                              
/* encodes a PA-GSS from a GSS-TOKEN and a PA-GSS-STATE */                              
krb5_error_code encode_pa_gss(gss_buffer_t sec_ctx_token, 
                              krb5_data* pa_gss_state, 
                              krb5_pa_data** pa_gss_out);

/* fills the channel_bindings struct with the encoded_request_body as
   application data */
void fill_channel_bindings(krb5_data* encoded_request_body, 
                           gss_channel_bindings_t channel_bindings);
