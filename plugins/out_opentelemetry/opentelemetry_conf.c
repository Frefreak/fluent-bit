/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2022 The Fluent Bit Authors
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

#include <fluent-bit/flb_output_plugin.h>
#include <fluent-bit/flb_utils.h>
#include <fluent-bit/flb_pack.h>
#include <fluent-bit/flb_sds.h>
#include <fluent-bit/flb_kv.h>
#include <sys/stat.h>

#include "msgpack/unpack.h"
#include "opentelemetry.h"
#include "opentelemetry_conf.h"


static int read_label_map_spec(struct opentelemetry_context *ctx, flb_sds_t path)
{
    int ret;
    struct stat st;
    size_t file_size;
    size_t ret_size;
    FILE *fp;
    char *buf = NULL;
    char *msgpack_buf = NULL;
    int root_type;
    size_t off = 0;
    msgpack_unpacked *result;

    ret = access(path, R_OK);
    if (ret < 0) {
        flb_errno();
        flb_plg_error(ctx->ins, "can't access %s", path);
        return -1;
    }
    ret = stat(path, &st);
    if (ret < 0) {
        flb_errno();
        flb_plg_error(ctx->ins, "stat failed %s", path);
        return -1;
    }
    file_size = st.st_size;

    fp = fopen(path, "r");
    if (fp == NULL) {
        flb_plg_error(ctx->ins, "can't open %s", path);
        return -1;
    }

    buf = flb_malloc(file_size);
    if (buf == NULL) {
        flb_plg_error(ctx->ins, "malloc failed for file size %ld", file_size);
        fclose(fp);
        return -1;
    }

    ret_size = fread(buf, 1, file_size, fp);
    if (ret_size < file_size && feof(fp) != 0) {
        flb_plg_error(ctx->ins, "fread failed");
        fclose(fp);
        flb_free(buf);
        return -1;
    }
    ret = flb_pack_json(buf, ret_size, &msgpack_buf, &ret_size, &root_type, NULL);
    if (ret < 0) {
        flb_plg_error(ctx->ins, "flb_pack_json failed");
        fclose(fp);
        flb_free(buf);
        return -1;
    }
    fclose(fp);
    flb_free(buf);

    result = flb_malloc(sizeof(msgpack_unpacked));
    if (result == NULL) {
        flb_plg_error(ctx->ins, "malloc failed for msgpack_unpacked");
        return -1;
    }

    msgpack_unpacked_init(result);
    if (msgpack_unpack_next(result, msgpack_buf, ret_size, &off) == MSGPACK_UNPACK_SUCCESS) {
        flb_plg_debug(ctx->ins, "msgpack unpack success");
        if (result->data.type != MSGPACK_OBJECT_MAP) {
            flb_plg_error(ctx->ins, "non map msgpack object detected");
            return -1;
        }

        ctx->label_map_spec = &result->data;
        ctx->label_map_result = result;
        ctx->msgpack_buffer = msgpack_buf;
    } else {
        flb_plg_error(ctx->ins, "msgpack unpack failed");
    }
    return 0;
}

static int config_add_labels(struct flb_output_instance *ins,
                             struct opentelemetry_context *ctx)
{
    struct mk_list *head;
    struct flb_config_map_val *mv;
    struct flb_slist_entry *k = NULL;
    struct flb_slist_entry *v = NULL;
    struct flb_kv *kv;

    if (!ctx->add_labels || mk_list_size(ctx->add_labels) == 0) {
        return 0;
    }

    /* iterate all 'add_label' definitions */
    flb_config_map_foreach(head, mv, ctx->add_labels) {
        if (mk_list_size(mv->val.list) != 2) {
            flb_plg_error(ins, "'add_label' expects a key and a value, "
                          "e.g: 'add_label version 1.8.0'");
            return -1;
        }

        k = mk_list_entry_first(mv->val.list, struct flb_slist_entry, _head);
        v = mk_list_entry_last(mv->val.list, struct flb_slist_entry, _head);

        kv = flb_kv_item_create(&ctx->kv_labels, k->str, v->str);
        if (!kv) {
            flb_plg_error(ins, "could not append label %s=%s\n", k->str, v->str);
            return -1;
        }
    }

    return 0;
}

static int config_label_map_path(struct opentelemetry_context *ctx)
{
    int ret;
    ctx->label_map_spec = NULL;
    if (ctx->label_map_path) {
        flb_debug("reading label map spec from %s", ctx->label_map_path);
        ret = read_label_map_spec(ctx, ctx->label_map_path);
        if (ret < 0) {
            return -1;
        }
    }
    return 0;
}

/*
* Check if a Proxy have been set, if so the Upstream manager will use
* the Proxy end-point and then we let the HTTP client know about it, so
* it can adjust the HTTP requests.
*/

static void check_proxy(struct flb_output_instance *ins,
                        struct opentelemetry_context *ctx,
                        char *host, char *port,
                        char *protocol, char *uri){

    const char *tmp = NULL;
    int ret;
    tmp = flb_output_get_property("proxy", ins);
    if (tmp) {
        ret = flb_utils_url_split(tmp, &protocol, &host, &port, &uri);
        if (ret == -1) {
            flb_plg_error(ctx->ins, "could not parse proxy parameter: '%s'", tmp);
            flb_free(ctx);
        }

        ctx->proxy_host = host;
        ctx->proxy_port = atoi(port);
        ctx->proxy = tmp;
        flb_free(protocol);
        flb_free(port);
        flb_free(uri);
        uri = NULL;
    }
    else {
        flb_output_net_default("127.0.0.1", 80, ins);
    }
}

static char *sanitize_uri(char *uri){
    char *new_uri;
    int   uri_len;

    if (uri == NULL) {
        uri = flb_strdup("/");
    }
    else if (uri[0] != '/') {
        uri_len = strlen(uri);
        new_uri = flb_calloc(uri_len + 2, sizeof(char));

        if (new_uri != NULL) {
            new_uri[0] = '/';

            strncat(new_uri, uri, uri_len + 1);
        }

        uri = new_uri;
    }

    /* This function could return NULL if flb_calloc fails */

    return uri;
}

struct opentelemetry_context *flb_opentelemetry_context_create(
    struct flb_output_instance *ins, struct flb_config *config)
{
    int ret;
    int io_flags = 0;
    char *protocol = NULL;
    char *host = NULL;
    char *port = NULL;
    char *metrics_uri = NULL;
    char *traces_uri = NULL;
    char *logs_uri = NULL;
    struct flb_upstream *upstream;
    struct opentelemetry_context *ctx = NULL;
    const char *tmp = NULL;

    /* Allocate plugin context */
    ctx = flb_calloc(1, sizeof(struct opentelemetry_context));
    if (!ctx) {
        flb_errno();
        return NULL;
    }
    ctx->ins = ins;
    mk_list_init(&ctx->kv_labels);

    ret = flb_output_config_map_set(ins, (void *) ctx);
    if (ret == -1) {
        flb_free(ctx);
        return NULL;
    }

    /* Parse 'add_label' */
    ret = config_add_labels(ins, ctx);
    if (ret == -1) {
        return NULL;
    }

    /* Parse 'label_map_path' */
    ret = config_label_map_path(ctx);
    if (ret == -1) {
        return NULL;
    }

    check_proxy(ins, ctx, host, port, protocol, metrics_uri);
    check_proxy(ins, ctx, host, port, protocol, logs_uri);

    /* Check if SSL/TLS is enabled */
#ifdef FLB_HAVE_TLS
    if (ins->use_tls == FLB_TRUE) {
        io_flags = FLB_IO_TLS;
    }
    else {
        io_flags = FLB_IO_TCP;
    }
#else
    io_flags = FLB_IO_TCP;
#endif

    if (ins->host.ipv6 == FLB_TRUE) {
        io_flags |= FLB_IO_IPV6;
    }

    if (ctx->proxy) {
        flb_plg_trace(ctx->ins, "Upstream Proxy=%s:%i",
                      ctx->proxy_host, ctx->proxy_port);
        upstream = flb_upstream_create(config,
                                       ctx->proxy_host,
                                       ctx->proxy_port,
                                       io_flags, ins->tls);
    }
    else {
        upstream = flb_upstream_create(config,
                                       ins->host.name,
                                       ins->host.port,
                                       io_flags, ins->tls);
    }

    if (!upstream) {
        flb_free(ctx);
        return NULL;
    }

    logs_uri = sanitize_uri(ctx->logs_uri);
    traces_uri = sanitize_uri(ctx->traces_uri);
    metrics_uri = sanitize_uri(ctx->metrics_uri);

    ctx->u = upstream;
    ctx->host = ins->host.name;
    ctx->port = ins->host.port;

    if (logs_uri == NULL) {
        flb_plg_trace(ctx->ins,
                      "Could not allocate memory for sanitized "
                      "log endpoint uri");
    }
    else {
        ctx->logs_uri = logs_uri;
    }

    if (traces_uri == NULL) {
        flb_plg_trace(ctx->ins,
                      "Could not allocate memory for sanitized "
                      "trace endpoint uri");
    }
    else {
        ctx->traces_uri = traces_uri;
    }

    if (metrics_uri == NULL) {
        flb_plg_trace(ctx->ins,
                      "Could not allocate memory for sanitized "
                      "metric endpoint uri");
    }
    else {
        ctx->metrics_uri = metrics_uri;
    }


    /* Set instance flags into upstream */
    flb_output_upstream_set(ctx->u, ins);

    tmp = flb_output_get_property("compress", ins);
    ctx->compress_gzip = FLB_FALSE;
    if (tmp) {
        if (strcasecmp(tmp, "gzip") == 0) {
            ctx->compress_gzip = FLB_TRUE;
        }
    }

    return ctx;
}

void flb_opentelemetry_context_destroy(
    struct opentelemetry_context *ctx)
{
    if (!ctx) {
        return;
    }

    flb_kv_release(&ctx->kv_labels);
    if (ctx->label_map_spec) {
        msgpack_unpacked_destroy(ctx->label_map_result);
        flb_free(ctx->label_map_result);
        flb_free(ctx->msgpack_buffer);
    }

    if (ctx->u) {
        flb_upstream_destroy(ctx->u);
    }

    flb_free(ctx->proxy_host);
    flb_free(ctx);
}
