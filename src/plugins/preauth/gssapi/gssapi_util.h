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

#include <krb5/krb5.h>
#include <gssapi/gssapi_ext.h>

/* These are not standardized values. They're defined here only to make it
   easier its modification within this module. */
#define KRB5_PADATA_GSS         200
#define AUTHZ_GSS_ATTRIBUTE     200
#define PA_GSS_KEYUSAGE         512

/* Federated principal name */
#define KRB5_FEDERATED_PRINCSTR "FEDERATED"

/* indicate the max size of a PRF result for safety array alloc */
#define MAX_PRF_SIZE            200

/* prints a data array in hex format, prepending the indicated text string */
void print_buffer(char *text, unsigned char* data, int length);

/* prints a data array in text format, prepending the indicated text string */
void print_buffer_txt(char *text, unsigned char* data, int length);

/* fills a gss buffer with a copy of the data provided */
krb5_error_code fill_gss_buffer_from_data(void *data, unsigned int length,
                               gss_buffer_t gss_buffer);

/* prints the GSS error in a textual form */
void display_gss_status(OM_uint32 maj_stat, OM_uint32 min_stat);

/* fills the channel_bindings struct with the encoded_request_body as
   application data */
void fill_channel_bindings(krb5_data* encoded_request_body,
                           gss_channel_bindings_t channel_bindings);
                           
/* imports a GSS_NAME from a KRB5_PRINC */
krb5_error_code gss_import_name_from_krb5_principal(krb5_const_principal princ, 
                                                    gss_name_t *name);
