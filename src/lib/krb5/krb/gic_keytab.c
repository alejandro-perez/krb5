/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/* lib/krb5/krb/gic_keytab.c */
/*
 * Copyright (C) 2002, 2003, 2008 by the Massachusetts Institute of Technology.
 * All rights reserved.
 *
 * Export of this software from the United States of America may
 *   require a specific license from the United States Government.
 *   It is the responsibility of any person or organization contemplating
 *   export to obtain such a license before exporting.
 *
 * WITHIN THAT CONSTRAINT, permission to use, copy, modify, and
 * distribute this software and its documentation for any purpose and
 * without fee is hereby granted, provided that the above copyright
 * notice appear in all copies and that both that copyright notice and
 * this permission notice appear in supporting documentation, and that
 * the name of M.I.T. not be used in advertising or publicity pertaining
 * to distribution of the software without specific, written prior
 * permission.  Furthermore if you modify this software you must label
 * your software as modified software and not distribute it in such a
 * fashion that it might be confused with the original M.I.T. software.
 * M.I.T. makes no representations about the suitability of
 * this software for any purpose.  It is provided "as is" without express
 * or implied warranty.
 */
#ifndef LEAN_CLIENT

#include "k5-int.h"
#include "int-proto.h"
#include "init_creds_ctx.h"

static krb5_error_code
get_as_key_keytab(krb5_context context,
                  krb5_principal client,
                  krb5_enctype etype,
                  krb5_prompter_fct prompter,
                  void *prompter_data,
                  krb5_data *salt,
                  krb5_data *params,
                  krb5_keyblock *as_key,
                  void *gak_data)
{
    krb5_keytab keytab = (krb5_keytab) gak_data;
    krb5_error_code ret;
    krb5_keytab_entry kt_ent;
    krb5_keyblock *kt_key;

    /* if there's already a key of the correct etype, we're done.
       if the etype is wrong, free the existing key, and make
       a new one. */

    if (as_key->length) {
        if (as_key->enctype == etype)
            return(0);

        krb5_free_keyblock_contents(context, as_key);
        as_key->length = 0;
    }

    if (!krb5_c_valid_enctype(etype))
        return(KRB5_PROG_ETYPE_NOSUPP);

    if ((ret = krb5_kt_get_entry(context, keytab, client,
                                 0, /* don't have vno available */
                                 etype, &kt_ent)))
        return(ret);

    ret = krb5_copy_keyblock(context, &kt_ent.key, &kt_key);

    /* again, krb5's memory management is lame... */

    *as_key = *kt_key;
    free(kt_key);

    (void) krb5_kt_free_entry(context, &kt_ent);

    return(ret);
}

/* Return the list of etypes available for client in keytab. */
static krb5_error_code
lookup_etypes_for_keytab(krb5_context context, krb5_keytab keytab,
                         krb5_principal client, krb5_enctype **etypes_out)
{
    krb5_kt_cursor cursor;
    krb5_keytab_entry entry;
    krb5_enctype *p, *etypes = NULL;
    krb5_kvno max_kvno = 0;
    krb5_error_code ret;
    size_t count = 0;

    *etypes_out = NULL;

    if (keytab->ops->start_seq_get == NULL)
        return EINVAL;
    ret = krb5_kt_start_seq_get(context, keytab, &cursor);
    if (ret != 0)
        return ret;

    for (;;) {
        ret = krb5_kt_next_entry(context, keytab, &entry, &cursor);
        if (ret == KRB5_KT_END)
            break;
        if (ret)
            goto cleanup;

        if (!krb5_c_valid_enctype(entry.key.enctype))
            continue;
        if (!krb5_principal_compare(context, entry.principal, client))
            continue;
        /* Make sure our list is for the highest kvno found for client. */
        if (entry.vno > max_kvno) {
            free(etypes);
            etypes = NULL;
            count = 0;
            max_kvno = entry.vno;
        } else if (entry.vno != max_kvno)
            continue;

        /* Leave room for the terminator and possibly a second entry. */
        p = realloc(etypes, (count + 3) * sizeof(*etypes));
        if (p == NULL) {
            ret = ENOMEM;
            goto cleanup;
        }
        etypes = p;
        etypes[count++] = entry.key.enctype;
        /* All DES key types work with des-cbc-crc, which is more likely to be
         * accepted by the KDC (since MIT KDCs refuse des-cbc-md5). */
        if (entry.key.enctype == ENCTYPE_DES_CBC_MD5 ||
            entry.key.enctype == ENCTYPE_DES_CBC_MD4)
            etypes[count++] = ENCTYPE_DES_CBC_CRC;
        etypes[count] = 0;
    }

    ret = 0;
    *etypes_out = etypes;
    etypes = NULL;
cleanup:
    krb5_kt_end_seq_get(context, keytab, &cursor);
    free(etypes);
    return ret;
}

/* Return true if search_for is in etype_list. */
static krb5_boolean
check_etypes_have(krb5_enctype *etype_list, krb5_enctype search_for)
{
    int i;

    if (!etype_list)
        return FALSE;

    for (i = 0; etype_list[i] != 0; i++) {
        if (etype_list[i] == search_for)
            return TRUE;
    }

    return FALSE;
}

krb5_error_code KRB5_CALLCONV
krb5_init_creds_set_keytab(krb5_context context,
                           krb5_init_creds_context ctx,
                           krb5_keytab keytab)
{
    krb5_enctype *etype_list;
    krb5_error_code ret;
    int i, j;
    char *name;

    ctx->gak_fct = get_as_key_keytab;
    ctx->gak_data = keytab;

    ret = lookup_etypes_for_keytab(context, keytab, ctx->request->client,
                                   &etype_list);
    if (ret) {
        TRACE_INIT_CREDS_KEYTAB_LOOKUP_FAILED(context, ret);
        return 0;
    }

    TRACE_INIT_CREDS_KEYTAB_LOOKUP(context, etype_list);

    /* Filter the ktypes list based on what's in the keytab */
    for (i = 0, j = 0; i < ctx->request->nktypes; i++) {
        if (check_etypes_have(etype_list, ctx->request->ktype[i])) {
            ctx->request->ktype[j] = ctx->request->ktype[i];
            j++;
        }
    }
    ctx->request->nktypes = j;
    free(etype_list);

    /* Error out now if there's no overlap. */
    if (ctx->request->nktypes == 0) {
        ret = krb5_unparse_name(context, ctx->request->client, &name);
        if (ret == 0) {
            krb5_set_error_message(context, KRB5_KT_NOTFOUND,
                                   _("Keytab contains no suitable keys for "
                                     "%s"), name);
        }
        krb5_free_unparsed_name(context, name);
        return KRB5_KT_NOTFOUND;
    }

    return 0;
}

static krb5_error_code
get_init_creds_keytab(krb5_context context, krb5_creds *creds,
                      krb5_principal client, krb5_keytab keytab,
                      krb5_deltat start_time, const char *in_tkt_service,
                      krb5_get_init_creds_opt *options, int *use_master)
{
    krb5_error_code ret;
    krb5_init_creds_context ctx = NULL;

    ret = krb5_init_creds_init(context, client, NULL, NULL, start_time,
                               options, &ctx);
    if (ret != 0)
        goto cleanup;

    if (in_tkt_service) {
        ret = krb5_init_creds_set_service(context, ctx, in_tkt_service);
        if (ret != 0)
            goto cleanup;
    }

    ret = krb5_init_creds_set_keytab(context, ctx, keytab);
    if (ret != 0)
        goto cleanup;

    ret = k5_init_creds_get(context, ctx, use_master);
    if (ret != 0)
        goto cleanup;

    ret = krb5_init_creds_get_creds(context, ctx, creds);
    if (ret != 0)
        goto cleanup;

cleanup:
    krb5_init_creds_free(context, ctx);

    return ret;
}

krb5_error_code KRB5_CALLCONV
krb5_get_init_creds_keytab(krb5_context context,
                           krb5_creds *creds,
                           krb5_principal client,
                           krb5_keytab arg_keytab,
                           krb5_deltat start_time,
                           const char *in_tkt_service,
                           krb5_get_init_creds_opt *options)
{
    krb5_error_code ret, ret2;
    int use_master;
    krb5_keytab keytab;

    if (arg_keytab == NULL) {
        if ((ret = krb5_kt_default(context, &keytab)))
            return ret;
    } else {
        keytab = arg_keytab;
    }

    use_master = 0;

    /* first try: get the requested tkt from any kdc */

    ret = get_init_creds_keytab(context, creds, client, keytab, start_time,
                                in_tkt_service, options, &use_master);

    /* check for success */

    if (ret == 0)
        goto cleanup;

    /* If all the kdc's are unavailable fail */

    if ((ret == KRB5_KDC_UNREACH) || (ret == KRB5_REALM_CANT_RESOLVE))
        goto cleanup;

    /* if the reply did not come from the master kdc, try again with
       the master kdc */

    if (!use_master) {
        use_master = 1;

        ret2 = get_init_creds_keytab(context, creds, client, keytab,
                                     start_time, in_tkt_service, options,
                                     &use_master);

        if (ret2 == 0) {
            ret = 0;
            goto cleanup;
        }

        /* if the master is unreachable, return the error from the
           slave we were able to contact */

        if ((ret2 == KRB5_KDC_UNREACH) ||
            (ret2 == KRB5_REALM_CANT_RESOLVE) ||
            (ret2 == KRB5_REALM_UNKNOWN))
            goto cleanup;

        ret = ret2;
    }

    /* at this point, we have a response from the master.  Since we don't
       do any prompting or changing for keytabs, that's it. */

cleanup:
    if (arg_keytab == NULL)
        krb5_kt_close(context, keytab);

    return(ret);
}
krb5_error_code KRB5_CALLCONV
krb5_get_in_tkt_with_keytab(krb5_context context, krb5_flags options,
                            krb5_address *const *addrs, krb5_enctype *ktypes,
                            krb5_preauthtype *pre_auth_types,
                            krb5_keytab arg_keytab, krb5_ccache ccache,
                            krb5_creds *creds, krb5_kdc_rep **ret_as_reply)
{
    krb5_error_code retval;
    krb5_get_init_creds_opt *opts;
    char * server = NULL;
    krb5_keytab keytab;
    krb5_principal client_princ, server_princ;
    int use_master = 0;

    retval = krb5int_populate_gic_opt(context, &opts,
                                      options, addrs, ktypes,
                                      pre_auth_types, creds);
    if (retval)
        return retval;

    if (arg_keytab == NULL) {
        retval = krb5_kt_default(context, &keytab);
        if (retval)
            goto cleanup;
    }
    else keytab = arg_keytab;

    retval = krb5_unparse_name( context, creds->server, &server);
    if (retval)
        goto cleanup;
    server_princ = creds->server;
    client_princ = creds->client;
    retval = krb5int_get_init_creds(context, creds, creds->client,
                                    krb5_prompter_posix,  NULL,
                                    0, server, opts,
                                    get_as_key_keytab, (void *)keytab,
                                    &use_master, ret_as_reply);
    krb5_free_unparsed_name( context, server);
    if (retval) {
        goto cleanup;
    }
    krb5_free_principal(context, creds->server);
    krb5_free_principal(context, creds->client);
    creds->client = client_princ;
    creds->server = server_princ;

    /* store it in the ccache! */
    if (ccache)
        if ((retval = krb5_cc_store_cred(context, ccache, creds)))
            goto cleanup;
cleanup:
    krb5_get_init_creds_opt_free(context, opts);
    if (arg_keytab == NULL)
        krb5_kt_close(context, keytab);
    return retval;
}

#endif /* LEAN_CLIENT */
