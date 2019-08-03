
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Roman Arutyunyan
 * Copyright (C) Nginx, Inc.
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#define NGX_FLV_HEADER_SIGVER           0x464c5601

#define NGX_FLV_HEADER_VIDEO            0x01
#define NGX_FLV_HEADER_AUDIO            0x04

#define NGX_FLV_TAG_TYPE_AUDIO          0x08
#define NGX_FLV_TAG_TYPE_VIDEO          0x09
#define NGX_FLV_TAG_TYPE_META           0x12

#define NGX_FLV_TAG_TYPE_MASK           0x1f

#define NGX_FLV_PACKET_AVC              0x07
#define NGX_FLV_PACKET_AAC              0x0a

#define NGX_FLV_AUDIO_CODECID_MASK      0xf0

#define NGX_FLV_VIDEO_CODECID_MASK      0x0f
#define NGX_FLV_VIDEO_FRAMETYPE_MASK    0xf0


typedef struct {
    u_char          signature[3];       /* "FLV" */
    u_char          version[1];         /* 0x01 [version 1] */
    u_char          av_flags[1];        /* 0b00000 1[a] 0 1[v] */
    u_char          length[4];          /* 0x00000009 */
    u_char          tag_size[4];        /* 0x00000000 */
} ngx_flv_header_t;


typedef struct {
    u_char          type[1];            /* 0b00 0[filter] 00000[type] */
    u_char          size[3];            /* message length */
    u_char          timestamp[3];       /* pts in milliseconds */
    u_char          timestamp_ext[1];   /* upper 8 bits of timestamp */
    u_char          stream_id[3];       /* 0x000000 */

    /* Audio: 0b0000[codec_id] 00[rate] 0[size] 0[type]
     * Video: 0b0000[type] 0000[codec_id] */
    u_char          av_header[1];

    /* Audio or Video: 0x00 is sequence_header */
    u_char          av_type[1];
} ngx_flv_tag_header_t;


#define NGX_FLV_HEADER_SIZE      sizeof(ngx_flv_header_t)
#define NGX_FLV_PREV_TAG_SIZE    4
#define NGX_FLV_TAG_HEADER_SIZE  11
#define NGX_FLV_HEADER_LENGTH    (NGX_FLV_HEADER_SIZE - NGX_FLV_PREV_TAG_SIZE)

#define ngx_flv_get_tag_size(p)                                               \
    ( ((uint32_t) ((u_char *) (p))[0] << 16)                                  \
    + (           ((u_char *) (p))[1] << 8)                                   \
    + (           ((u_char *) (p))[2]) )

#define ngx_flv_get_timestamp(p)                                              \
    ( ((uint32_t) ((u_char *) (p))[3] << 24)                                  \
    + (           ((u_char *) (p))[0] << 16)                                  \
    + (           ((u_char *) (p))[1] << 8)                                   \
    + (           ((u_char *) (p))[2]) )

#define ngx_flv_get_32value(p)                                                \
    ( ((uint32_t) ((u_char *) (p))[0] << 24)                                  \
    + (           ((u_char *) (p))[1] << 16)                                  \
    + (           ((u_char *) (p))[2] << 8)                                   \
    + (           ((u_char *) (p))[3]) )

#define ngx_flv_get_64value(p)                                                \
    ( ((uint64_t) ((u_char *) (p))[0] << 56)                                  \
    + ((uint64_t) ((u_char *) (p))[1] << 48)                                  \
    + ((uint64_t) ((u_char *) (p))[2] << 40)                                  \
    + ((uint64_t) ((u_char *) (p))[3] << 32)                                  \
    + ((uint64_t) ((u_char *) (p))[4] << 24)                                  \
    + (           ((u_char *) (p))[5] << 16)                                  \
    + (           ((u_char *) (p))[6] << 8)                                   \
    + (           ((u_char *) (p))[7]) )

#define ngx_flv_header_has_signature_version(p)                               \
    (ngx_flv_get_32value(p) == NGX_FLV_HEADER_SIGVER)

#define ngx_flv_header_has_audio(p)                                           \
    (((u_char *) (p))[0] & NGX_FLV_HEADER_AUDIO)

#define ngx_flv_header_has_video(p)                                           \
    (((u_char *) (p))[0] & NGX_FLV_HEADER_VIDEO)

#define ngx_flv_tag_type(p)                                                   \
    (((u_char *) (p))[0] & NGX_FLV_TAG_TYPE_MASK)

#define ngx_flv_tag_is_video(p)                                               \
    (ngx_flv_tag_type(p) == NGX_FLV_TAG_TYPE_VIDEO)

#define ngx_flv_tag_is_audio(p)                                               \
    (ngx_flv_tag_type(p) == NGX_FLV_TAG_TYPE_AUDIO)

#define ngx_flv_tag_is_meta(p)                                                \
    (ngx_flv_tag_type(p) == NGX_FLV_TAG_TYPE_META)

#define ngx_flv_is_sequence_header(p)   (((u_char *) (p))[0] == 0x00)

#define ngx_flv_codec_is_avc(p)                                               \
    ((((u_char *) (p))[0] & NGX_FLV_VIDEO_CODECID_MASK) == NGX_FLV_PACKET_AVC)

#define ngx_flv_video_frametype(p)                                            \
    ((((u_char *) (p))[0] & NGX_FLV_VIDEO_FRAMETYPE_MASK) >> 4)

#define ngx_flv_video_is_keyframe(p)    (ngx_flv_video_frametype(p) == 0x01)

#define ngx_flv_codec_is_aac(p)                                               \
    (((((u_char *) (p))[0] & NGX_FLV_AUDIO_CODECID_MASK) >> 4)                \
    == NGX_FLV_PACKET_AAC)

/* basic types */
#define NGX_AMF_NUMBER             0x00
#define NGX_AMF_BOOLEAN            0x01
#define NGX_AMF_STRING             0x02
#define NGX_AMF_OBJECT             0x03
#define NGX_AMF_NULL               0x05
#define NGX_AMF_ARRAY_NULL         0x06
#define NGX_AMF_MIXED_ARRAY        0x08
#define NGX_AMF_END                0x09
#define NGX_AMF_ARRAY              0x0a

/* extended types */
#define NGX_AMF_INT8               0x0100
#define NGX_AMF_INT16              0x0101
#define NGX_AMF_INT32              0x0102
#define NGX_AMF_VARIANT_           0x0103

/* r/w flags */
#define NGX_AMF_OPTIONAL           0x1000
#define NGX_AMF_TYPELESS           0x2000
#define NGX_AMF_CONTEXT            0x4000


static ngx_inline double
ngx_flv_get_amf_number(u_char *p)
{
    union {
        uint64_t  i;
        double    f;
    } uint2double;

    uint2double.i = ngx_flv_get_64value(p);

    return uint2double.f;
}


typedef struct {
    ngx_int_t             type;
    ngx_str_t             name;
    void                 *data;
    size_t                len;
} ngx_amf_elt_t;


typedef ngx_chain_t * (*ngx_amf_alloc_pt)(void *arg);


typedef struct {
    size_t                offset;
    ngx_chain_t          *link;
    ngx_chain_t          *first;
    ngx_log_t            *log;
    void                 *arg;
    ngx_amf_alloc_pt      alloc;
} ngx_amf_ctx_t;


typedef struct {
    size_t                buffer_size;
    size_t                max_buffer_size;
    ngx_flag_t            time_shift;
} ngx_http_flv_conf_t;


typedef struct {
    ngx_file_t            file;
    ngx_http_request_t   *request;

    u_char               *buffer;
    u_char               *buffer_start;
    u_char               *buffer_pos;
    u_char               *buffer_end;
    size_t                buffer_size;

    off_t                 offset;
    off_t                 file_end;
    off_t                 sequence_end;
    off_t                 sequence_len;
    off_t                 metadata_len;
    off_t                 start_offset;
    off_t                 end_offset;
    ngx_uint_t            start;
    ngx_uint_t            end;

    unsigned              has_audio:1;
    unsigned              has_video:1;
    unsigned              met_audio:1;
    unsigned              met_video:1;
    unsigned              aac_audio:1;
    unsigned              avc_video:1;

    ngx_chain_t          *out;
    ngx_chain_t           metadata;
    ngx_chain_t           audio_sequence_header;
    ngx_chain_t           video_sequence_header;

    ngx_buf_t             metadata_buf;
    ngx_buf_t             audio_sequence_buf;
    ngx_buf_t             video_sequence_buf;

    u_char               *filepositions;
    u_char               *times;
    uint32_t              filepositions_nelts;
    uint32_t              times_nelts;
} ngx_http_flv_file_t;


#define ngx_http_flv_tag_next(flv, n)                                         \
    flv->buffer_pos += (size_t) n;                                            \
    flv->offset += n


static ngx_int_t ngx_http_flv_handler(ngx_http_request_t *r);
static ngx_int_t ngx_http_flv_atofp(u_char *line, size_t n, size_t point);

static ngx_int_t ngx_http_flv_process(ngx_http_flv_file_t *flv);
static ngx_int_t ngx_http_flv_read(ngx_http_flv_file_t *flv, size_t size);
static ngx_int_t ngx_http_flv_read_header(ngx_http_flv_file_t *flv);
static ngx_int_t ngx_http_flv_read_metadata(ngx_http_flv_file_t *flv);
static ngx_int_t ngx_http_flv_read_tags(ngx_http_flv_file_t *flv);
static ngx_int_t ngx_http_flv_parse_metadata(ngx_http_flv_file_t *flv);
static off_t ngx_http_flv_timestamp_to_offset(ngx_http_flv_file_t *flv,
    ngx_uint_t timestamp, ngx_uint_t start);
static ngx_int_t ngx_amf_read(ngx_amf_ctx_t *ctx, ngx_amf_elt_t *elts,
    size_t nelts);

static char *ngx_http_flv(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static void *ngx_http_flv_create_conf(ngx_conf_t *cf);
static char *ngx_http_flv_merge_conf(ngx_conf_t *cf, void *parent, void *child);


static ngx_command_t  ngx_http_flv_commands[] = {

    { ngx_string("flv"),
      NGX_HTTP_LOC_CONF|NGX_CONF_NOARGS,
      ngx_http_flv,
      0,
      0,
      NULL },

    { ngx_string("flv_time_shift"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_flv_conf_t, time_shift),
      NULL },

    { ngx_string("flv_buffer_size"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_flv_conf_t, buffer_size),
      NULL },

    { ngx_string("flv_max_buffer_size"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_flv_conf_t, max_buffer_size),
      NULL },

      ngx_null_command
};


static ngx_http_module_t  ngx_http_flv_module_ctx = {
    NULL,                          /* preconfiguration */
    NULL,                          /* postconfiguration */

    NULL,                          /* create main configuration */
    NULL,                          /* init main configuration */

    NULL,                          /* create server configuration */
    NULL,                          /* merge server configuration */

    ngx_http_flv_create_conf,      /* create location configuration */
    ngx_http_flv_merge_conf        /* merge location configuration */
};


ngx_module_t  ngx_http_flv_module = {
    NGX_MODULE_V1,
    &ngx_http_flv_module_ctx,      /* module context */
    ngx_http_flv_commands,         /* module directives */
    NGX_HTTP_MODULE,               /* module type */
    NULL,                          /* init master */
    NULL,                          /* init module */
    NULL,                          /* init process */
    NULL,                          /* init thread */
    NULL,                          /* exit thread */
    NULL,                          /* exit process */
    NULL,                          /* exit master */
    NGX_MODULE_V1_PADDING
};


static u_char     ngx_flv_header[] = "FLV\x1\x5\0\0\0\x9\0\0\0\0";


static ngx_int_t
ngx_http_flv_handler(ngx_http_request_t *r)
{
    off_t                      start, end, len;
    u_char                    *last;
    size_t                     root;
    ngx_str_t                  path, value;
    ngx_log_t                 *log;
    ngx_buf_t                 *b;
    ngx_int_t                  rc, time_start, time_end;
    ngx_uint_t                 level, i, time_shift;
    ngx_chain_t                out[2];
    ngx_http_flv_file_t       *flv;
    ngx_http_flv_conf_t       *conf;
    ngx_open_file_info_t       of;
    ngx_http_core_loc_conf_t  *clcf;

    if (!(r->method & (NGX_HTTP_GET|NGX_HTTP_HEAD))) {
        return NGX_HTTP_NOT_ALLOWED;
    }

    if (r->uri.data[r->uri.len - 1] == '/') {
        return NGX_DECLINED;
    }

    rc = ngx_http_discard_request_body(r);

    if (rc != NGX_OK) {
        return rc;
    }

    last = ngx_http_map_uri_to_path(r, &path, &root, 0);
    if (last == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    log = r->connection->log;

    path.len = last - path.data;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, log, 0,
                   "http flv filename: \"%V\"", &path);

    clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);

    ngx_memzero(&of, sizeof(ngx_open_file_info_t));

    of.read_ahead = clcf->read_ahead;
    of.directio = clcf->directio;
    of.valid = clcf->open_file_cache_valid;
    of.min_uses = clcf->open_file_cache_min_uses;
    of.errors = clcf->open_file_cache_errors;
    of.events = clcf->open_file_cache_events;

    if (ngx_http_set_disable_symlinks(r, clcf, &path, &of) != NGX_OK) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    if (ngx_open_cached_file(clcf->open_file_cache, &path, &of, r->pool)
        != NGX_OK)
    {
        switch (of.err) {

        case 0:
            return NGX_HTTP_INTERNAL_SERVER_ERROR;

        case NGX_ENOENT:
        case NGX_ENOTDIR:
        case NGX_ENAMETOOLONG:

            level = NGX_LOG_ERR;
            rc = NGX_HTTP_NOT_FOUND;
            break;

        case NGX_EACCES:
#if (NGX_HAVE_OPENAT)
        case NGX_EMLINK:
        case NGX_ELOOP:
#endif

            level = NGX_LOG_ERR;
            rc = NGX_HTTP_FORBIDDEN;
            break;

        default:

            level = NGX_LOG_CRIT;
            rc = NGX_HTTP_INTERNAL_SERVER_ERROR;
            break;
        }

        if (rc != NGX_HTTP_NOT_FOUND || clcf->log_not_found) {
            ngx_log_error(level, log, of.err,
                          "%s \"%s\" failed", of.failed, path.data);
        }

        return rc;
    }

    if (!of.is_file) {

        if (ngx_close_file(of.fd) == NGX_FILE_ERROR) {
            ngx_log_error(NGX_LOG_ALERT, log, ngx_errno,
                          ngx_close_file_n " \"%s\" failed", path.data);
        }

        return NGX_DECLINED;
    }

    r->root_tested = !r->error_page;

    conf = ngx_http_get_module_loc_conf(r, ngx_http_flv_module);
    time_shift = (ngx_uint_t) conf->time_shift;
    time_start = 0;
    time_end = -1;
    start = 0;
    end = of.size;
    len = of.size;
    i = 1;
    flv = NULL;

    if (r->args.len) {

        if (ngx_http_arg(r, (u_char *) "time_shift", 10, &value) == NGX_OK) {
            time_shift = 1;
        }

        if (ngx_http_arg(r, (u_char *) "start", 5, &value) == NGX_OK) {

            if (time_shift) {
                time_start = ngx_http_flv_atofp(value.data, value.len, 3);

            } else {
                start = ngx_atoof(value.data, value.len);

                if (start == NGX_ERROR || start >= len) {
                    start = 0;
                }

                if (start) {
                    len = sizeof(ngx_flv_header) - 1 + len - start;
                    i = 0;
                }
            }
        }

        if (time_shift
            && ngx_http_arg(r, (u_char *) "end", 3, &value) == NGX_OK)
        {
            time_end = ngx_http_flv_atofp(value.data, value.len, 3);

            if (time_end >= 0 && time_start < 0) {
                time_start = 0;
            }
        }
    }

    if (time_end > time_start) {
        ngx_log_debug2(NGX_LOG_DEBUG_HTTP, log, 0,
                       "http flv time_shift time_start=%i time_end=%i",
                       time_start, time_end);

        flv = ngx_pcalloc(r->pool, sizeof(ngx_http_flv_file_t));
        if (flv == NULL) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
        flv->file.fd = of.fd;
        flv->file.name = path;
        flv->file.log = r->connection->log;
        flv->file_end = of.size;
        flv->buffer_size = conf->buffer_size;
        flv->start = time_start;
        flv->end = time_end;
        flv->request = r;

        switch (ngx_http_flv_process(flv)) {

        case NGX_DECLINED:
            if (flv->buffer) {
                ngx_pfree(r->pool, flv->buffer);
            }

            ngx_pfree(r->pool, flv);
            flv = NULL;

            break;

        case NGX_OK:
            start = flv->start_offset;
            end = flv->end_offset;
            len = end - start;
            if (start > 0) {
                /* len += flv->metadata_len; */
                len += sizeof(ngx_flv_header) - 1 + flv->sequence_len;
                i = 0;
            }

            break;

        default: /* NGX_ERROR */
            if (flv->buffer) {
                ngx_pfree(r->pool, flv->buffer);
            }

            ngx_pfree(r->pool, flv);

            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
    }

    log->action = "sending flv to client";

    r->headers_out.status = NGX_HTTP_OK;
    r->headers_out.content_length_n = len;
    r->headers_out.last_modified_time = of.mtime;

    if (ngx_http_set_etag(r) != NGX_OK) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    if (ngx_http_set_content_type(r) != NGX_OK) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    if (i == 0) {
        b = ngx_calloc_buf(r->pool);
        if (b == NULL) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        b->pos = ngx_flv_header;
        b->last = ngx_flv_header + sizeof(ngx_flv_header) - 1;
        b->memory = 1;

        out[0].buf = b;
        out[0].next = &out[1];

        if (flv && flv->out) {
            out[0].next = flv->out;
            while (flv->out->next) {
                flv->out = flv->out->next;
            }
            flv->out->next = &out[1];
        }
    }


    b = ngx_calloc_buf(r->pool);
    if (b == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    b->file = ngx_pcalloc(r->pool, sizeof(ngx_file_t));
    if (b->file == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    r->allow_ranges = 1;

    rc = ngx_http_send_header(r);

    if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
        return rc;
    }

    b->file_pos = start;
    b->file_last = end;

    b->in_file = b->file_last ? 1: 0;
    b->last_buf = (r == r->main) ? 1 : 0;
    b->last_in_chain = 1;

    b->file->fd = of.fd;
    b->file->name = path;
    b->file->log = log;
    b->file->directio = of.is_directio;

    out[1].buf = b;
    out[1].next = NULL;

    return ngx_http_output_filter(r, &out[i]);
}


static ngx_int_t
ngx_http_flv_atofp(u_char *line, size_t n, size_t point)
{
    ngx_int_t   value, cutoff, cutlim;
    ngx_uint_t  dot;

    if (n == 0) {
        return NGX_ERROR;
    }

    cutoff = NGX_MAX_INT_T_VALUE / 10;
    cutlim = NGX_MAX_INT_T_VALUE % 10;

    dot = 0;

    for (value = 0; n--; line++) {

        if (*line == '.') {
            if (dot) {
                return NGX_ERROR;
            }

            dot = 1;
            continue;
        }

        if (*line < '0' || *line > '9') {
            return NGX_ERROR;
        }

        if (dot && point == 0) {
            continue;
        }

        if (value >= cutoff && (value > cutoff || *line - '0' > cutlim)) {
            return NGX_ERROR;
        }

        value = value * 10 + (*line - '0');
        point -= dot;
    }

    while (point--) {
        if (value > cutoff) {
            return NGX_ERROR;
        }

        value = value * 10;
    }

    return value;
}


static ngx_int_t
ngx_http_flv_process(ngx_http_flv_file_t *flv)
{
    ngx_int_t      rc;
    ngx_chain_t  **prev;

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, flv->file.log, 0,
                   "flv start:%ui, end:%ui", flv->start, flv->end);

    rc = ngx_http_flv_read_header(flv);
    if (rc != NGX_OK) {
        return rc;
    }

    rc = ngx_http_flv_read_metadata(flv);
    if (rc != NGX_OK) {
        return rc;
    }

    rc = ngx_http_flv_read_tags(flv);
    if (rc != NGX_OK) {
        return rc;
    }

    if (!flv->avc_video) {
        ngx_log_error(NGX_LOG_ERR, flv->file.log, 0,
                      "flv does not support time shift as codec is not avc");
        return NGX_DECLINED;
    }

    rc = ngx_http_flv_parse_metadata(flv);
    if (rc != NGX_OK) {
        return rc;
    }

    flv->start_offset = ngx_http_flv_timestamp_to_offset(flv, flv->start, 1);
    flv->end_offset = ngx_http_flv_timestamp_to_offset(flv, flv->end, 0);

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, flv->file.log, 0,
                   "flv start_offset:%O end_offset:%O",
                   flv->start_offset, flv->end_offset);

    if (flv->end_offset <= flv->start_offset) {
        return NGX_DECLINED;
    }

    prev = &flv->out;

    /*
    if (flv->metadata.buf) {
        *prev = &flv->metadata;
        prev = &flv->metadata.next;
    }
    */

    if (flv->audio_sequence_header.buf) {
        *prev = &flv->audio_sequence_header;
        prev = &flv->audio_sequence_header.next;
    }

    if (flv->video_sequence_header.buf) {
        *prev = &flv->video_sequence_header;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_flv_read(ngx_http_flv_file_t *flv, size_t size)
{
    ssize_t  n;

    if (flv->buffer_pos + size <= flv->buffer_end) {
        return NGX_OK;
    }

    if (flv->offset + (off_t) flv->buffer_size > flv->file_end) {
        flv->buffer_size = (size_t) (flv->file_end - flv->offset);
    }

    if (flv->buffer_size < size) {
        ngx_log_error(NGX_LOG_ERR, flv->file.log, 0,
                      "\"%s\" flv file truncated", flv->file.name.data);
        return NGX_ERROR;
    }

    if (flv->buffer == NULL) {
        flv->buffer = ngx_palloc(flv->request->pool, flv->buffer_size);
        if (flv->buffer == NULL) {
            return NGX_ERROR;
        }

        flv->buffer_start = flv->buffer;
    }

    n = ngx_read_file(&flv->file, flv->buffer_start, flv->buffer_size,
                      flv->offset);

    if (n == NGX_ERROR) {
        return NGX_ERROR;
    }

    if ((size_t) n != flv->buffer_size) {
        ngx_log_error(NGX_LOG_CRIT, flv->file.log, 0,
                      ngx_read_file_n " read only %z of %z from \"%s\"",
                      n, flv->buffer_size, flv->file.name.data);
        return NGX_ERROR;
    }

    flv->buffer_pos = flv->buffer_start;
    flv->buffer_end = flv->buffer_start + flv->buffer_size;

    return NGX_OK;
}


static ngx_int_t
ngx_http_flv_read_header(ngx_http_flv_file_t *flv)
{
    ngx_flv_header_t  *hdr;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, flv->file.log, 0, "flv header");

    if (ngx_http_flv_read(flv, NGX_FLV_HEADER_SIZE) != NGX_OK) {
        return NGX_ERROR;
    }

    if (!ngx_flv_header_has_signature_version(flv->buffer_pos)) {
        ngx_log_error(NGX_LOG_ERR, flv->file.log, 0,
                      "flv wrong signature or version");
        return NGX_ERROR;
    }

    hdr = (ngx_flv_header_t *) flv->buffer_pos;

    if (ngx_flv_get_32value(hdr->length) != NGX_FLV_HEADER_LENGTH) {
        ngx_log_error(NGX_LOG_ERR, flv->file.log, 0,
                      "flv wrong header length");
        return NGX_ERROR;
    }

    if (ngx_flv_get_32value(hdr->tag_size) != 0) {
        ngx_log_error(NGX_LOG_ERR, flv->file.log, 0,
                      "flv wrong header prev_tag size");
        return NGX_ERROR;
    }

    flv->has_video = ngx_flv_header_has_video(hdr->av_flags);
    flv->has_audio = ngx_flv_header_has_audio(hdr->av_flags);

    ngx_http_flv_tag_next(flv, NGX_FLV_HEADER_SIZE);

    return NGX_OK;
}


/*
 * Small excess buffer to process tags after metadata.
 */
#define NGX_HTTP_FLV_META_BUFFER_EXCESS  (16 * 1024)

static ngx_int_t
ngx_http_flv_read_metadata(ngx_http_flv_file_t *flv)
{
    uint32_t               size;
    ngx_buf_t             *buf;
    ngx_http_flv_conf_t   *conf;
    ngx_flv_tag_header_t  *tag;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, flv->file.log, 0, "flv metadata tag");

    if (ngx_http_flv_read(flv, NGX_FLV_HEADER_SIZE) != NGX_OK) {
        return NGX_ERROR;
    }

    tag = (ngx_flv_tag_header_t *) flv->buffer_pos;
    size = NGX_FLV_TAG_HEADER_SIZE + ngx_flv_get_tag_size(tag->size)
           + NGX_FLV_PREV_TAG_SIZE;

    if (!ngx_flv_tag_is_meta(tag->type)) {
        ngx_log_error(NGX_LOG_ERR, flv->file.log, 0,
                      "flv first tag is not metadata");
        return NGX_DECLINED;
    }

    if (size + NGX_HTTP_FLV_META_BUFFER_EXCESS > flv->buffer_size) {
        conf = ngx_http_get_module_loc_conf(flv->request, ngx_http_flv_module);

        if (size > conf->max_buffer_size) {
            ngx_log_error(NGX_LOG_ERR, flv->file.log, 0,
                          "\"%s\" flv metadata tag is too large:%D, "
                          "you may want to increase flv_max_buffer_size",
                          flv->file.name.data, size);
            return NGX_ERROR;
        }

        ngx_pfree(flv->request->pool, flv->buffer);
        flv->buffer = NULL;
        flv->buffer_pos = NULL;
        flv->buffer_end = NULL;

        flv->buffer_size = (size_t) size + NGX_HTTP_FLV_META_BUFFER_EXCESS;
    }

    if (ngx_http_flv_read(flv, (size_t) size) != NGX_OK) {
        return NGX_ERROR;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, flv->file.log, 0,
                   "flv metadata_len:%D", size);

    buf = &flv->metadata_buf;
    buf->temporary = 1;
    buf->pos = flv->buffer_pos;
    buf->last = flv->buffer_pos + size;

    flv->metadata.buf = buf;
    flv->metadata_len = size;

    ngx_http_flv_tag_next(flv, size);

    return NGX_OK;
}


static ngx_int_t
ngx_http_flv_read_tags(ngx_http_flv_file_t *flv)
{
    uint32_t               size;
    ngx_buf_t             *buf;
    ngx_flv_tag_header_t  *tag;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, flv->file.log, 0, "flv av tag");

    while (flv->buffer_pos + NGX_FLV_HEADER_SIZE < flv->buffer_end) {

        if (ngx_http_flv_read(flv, NGX_FLV_HEADER_SIZE) != NGX_OK) {
            return NGX_ERROR;
        }

        tag = (ngx_flv_tag_header_t *) flv->buffer_pos;
        size = NGX_FLV_TAG_HEADER_SIZE + ngx_flv_get_tag_size(tag->size)
               + NGX_FLV_PREV_TAG_SIZE;

        if (flv->buffer_pos + size > flv->buffer_end) {
            break;
        }

        switch ngx_flv_tag_type(tag->type) {

        case NGX_FLV_TAG_TYPE_AUDIO:
            if (flv->met_audio) {
                break;
            }
            flv->met_audio = 1;
            flv->aac_audio = ngx_flv_codec_is_aac(tag->av_header);
            if (flv->aac_audio && !ngx_flv_is_sequence_header(tag->av_type)) {
                ngx_log_error(NGX_LOG_ERR, flv->file.log, 0,
                              "flv first audio tag is not sequence header");
                return NGX_ERROR;
            }
            flv->sequence_len += size;
            flv->sequence_end = flv->offset + size;

            buf = &flv->audio_sequence_buf;
            buf->temporary = 1;
            buf->pos = flv->buffer_pos;
            buf->last = flv->buffer_pos + size;

            flv->audio_sequence_header.buf = buf;
            break;

        case NGX_FLV_TAG_TYPE_VIDEO:
            if (flv->met_video) {
                break;
            }
            flv->met_video = 1;
            flv->avc_video = ngx_flv_codec_is_avc(tag->av_header);
            if (flv->avc_video && !ngx_flv_is_sequence_header(tag->av_type)) {
                ngx_log_error(NGX_LOG_ERR, flv->file.log, 0,
                              "flv first video tag is not sequence header");
                return NGX_ERROR;
            }
            flv->sequence_len += size;
            flv->sequence_end = flv->offset + size;

            buf = &flv->video_sequence_buf;
            buf->temporary = 1;
            buf->pos = flv->buffer_pos;
            buf->last = flv->buffer_pos + size;

            flv->video_sequence_header.buf = buf;
            break;

        default:
            break;
        }

        if (flv->met_audio && flv->met_video) {
            ngx_log_debug1(NGX_LOG_DEBUG_HTTP, flv->file.log, 0,
                           "flv sequence_len:%O", flv->sequence_len);
            return NGX_OK;
        }

        ngx_http_flv_tag_next(flv, size);
    }

    ngx_log_error(NGX_LOG_ERR, flv->file.log, 0,
                  "flv no a/v tag found within %DB after metadata",
                  NGX_HTTP_FLV_META_BUFFER_EXCESS);

    return NGX_DECLINED;
}


static ngx_int_t
ngx_http_flv_parse_metadata(ngx_http_flv_file_t *flv)
{
    ngx_buf_t             buf, *b;
    ngx_chain_t           chain;
    ngx_amf_ctx_t         act;

    static ngx_amf_ctx_t  filepositions_ctx;
    static ngx_amf_ctx_t  times_ctx;

    static ngx_amf_elt_t  in_keyframes[] = {

        { NGX_AMF_ARRAY | NGX_AMF_CONTEXT,
          ngx_string("filepositions"),
          &filepositions_ctx, 0 },

        { NGX_AMF_ARRAY | NGX_AMF_CONTEXT,
          ngx_string("times"),
          &times_ctx, 0 }
    };

    static ngx_amf_elt_t  in_inf[] = {

        { NGX_AMF_OBJECT,
          ngx_string("keyframes"),
          in_keyframes, sizeof(in_keyframes) },
    };

    static ngx_amf_elt_t  in_elts[] = {

        { NGX_AMF_STRING,
          ngx_null_string,
          NULL, 0 },

        { NGX_AMF_OBJECT,
          ngx_null_string,
          in_inf, sizeof(in_inf) }
    };

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, flv->file.log, 0,
                   "flv parse metadata");

    /* parse metadata */
    ngx_memcpy(&buf, flv->metadata.buf, sizeof(ngx_buf_t));
    ngx_memzero(&act, sizeof(act));
    ngx_memzero(&chain, sizeof(ngx_chain_t));

    buf.pos += NGX_FLV_TAG_HEADER_SIZE;
    chain.buf = &buf;
    act.link = &chain;
    act.log = flv->file.log;

    ngx_memzero(&filepositions_ctx, sizeof(filepositions_ctx));
    ngx_memzero(&times_ctx, sizeof(times_ctx));

    if (ngx_amf_read(&act, in_elts, sizeof(in_elts) / sizeof(in_elts[0]))
        != NGX_OK)
    {
        ngx_log_error(NGX_LOG_ERR, flv->file.log, 0,
                      "flv metadata has no necessary element like keyframes");
        return NGX_DECLINED;
    }

    if (times_ctx.link) {
        b = times_ctx.link->buf;

        if (b->last - b->pos < (ngx_int_t) times_ctx.offset + 4) {
            ngx_log_error(NGX_LOG_ERR, flv->file.log, 0,
                          "flv failed to init times");
            return NGX_DECLINED;
        }

        flv->times_nelts = ngx_flv_get_32value(b->pos + times_ctx.offset);
        flv->times = b->pos + times_ctx.offset + 4;
    }

    if (filepositions_ctx.link) {
        b = filepositions_ctx.link->buf;

        if (b->last - b->pos < (ngx_int_t) filepositions_ctx.offset + 4) {
            ngx_log_error(NGX_LOG_ERR, flv->file.log, 0,
                          "flv failed to init filepositions");
            return NGX_DECLINED;
        }

        flv->filepositions_nelts =
                ngx_flv_get_32value(b->pos + filepositions_ctx.offset);
        flv->filepositions = b->pos + filepositions_ctx.offset + 4;
    }

    if (!flv->times_nelts || flv->times_nelts != flv->filepositions_nelts) {
        ngx_log_error(NGX_LOG_ERR, flv->file.log, 0, "flv invalid keyframes,"
                      " times_nelts:%D filepositions_nelts:%D",
                      flv->times_nelts, flv->filepositions_nelts);
        return NGX_DECLINED;
    }

    return NGX_OK;
}


static off_t
ngx_http_flv_timestamp_to_offset(ngx_http_flv_file_t *flv, ngx_uint_t timestamp,
    ngx_uint_t start)
{
    off_t        offset;
    u_char      *times, *filepositions;
    ngx_int_t    left, right, middle;
    ngx_uint_t   rv, first, last;

    times = flv->times;
    right = flv->times_nelts - 1;
    left = 0;

    first = (ngx_uint_t) (1000 * ngx_flv_get_amf_number(&times[left*9 + 1]));
    last = (ngx_uint_t) (1000 * ngx_flv_get_amf_number(&times[right*9 + 1]));

    if (start) {
        if (timestamp <= first) {
            return 0;
        }

    } else {
        if (timestamp >= last) {
            return flv->file_end;
        }
    }

    rv = 0;
    middle = 0;

    while (left <= right) {
        middle = (left + right) / 2;

        rv = (ngx_uint_t) (1000 * ngx_flv_get_amf_number(&times[middle*9 + 1]));

        if (rv > timestamp) {
            right = middle - 1;

        } else if (rv < timestamp) {
            left = middle + 1;

        } else {
            break;
        }
    }

    if (middle > 0 && timestamp < rv) {
        middle--;
    }

    filepositions = flv->filepositions;
    offset = (off_t) ngx_flv_get_amf_number(&filepositions[middle*9 + 1]);

    if (start) {
        if (offset <= flv->sequence_end) {
            return 0;
        }

    } else {
        if (middle >= flv->filepositions_nelts - 1) {
            return flv->file_end;
        }
    }

    return offset;
}


static ngx_inline void *
ngx_amf_reverse_copy(void *dst, void *src, size_t len)
{
    size_t  k;

    if (dst == NULL || src == NULL) {
        return NULL;
    }

    for (k = 0; k < len; ++k) {
        ((u_char*)dst)[k] = ((u_char*)src)[len - 1 - k];
    }

    return dst;
}

#define NGX_AMF_DEBUG_SIZE 16

#ifdef NGX_DEBUG
static void
ngx_amf_debug(ngx_log_t *log, const char *op, u_char *p, size_t n)
{
    size_t          i;
    u_char          hstr[3 * NGX_AMF_DEBUG_SIZE + 1];
    u_char          str[NGX_AMF_DEBUG_SIZE + 1];
    u_char         *hp, *sp;
    static u_char   hex[] = "0123456789ABCDEF";

    hp = hstr;
    sp = str;

    for (i = 0; i < n && i < NGX_AMF_DEBUG_SIZE; ++i) {
        *hp++ = ' ';
        if (p) {
            *hp++ = hex[(*p & 0xf0) >> 4];
            *hp++ = hex[*p & 0x0f];
            *sp++ = (*p >= 0x20 && *p <= 0x7e) ?
                    *p : (u_char)'?';
            ++p;
        } else {
            *hp++ = 'X';
            *hp++ = 'X';
            *sp++ = '?';
        }
    }
    *hp = *sp = '\0';

    ngx_log_debug4(NGX_LOG_DEBUG_CORE, log, 0,
                   "AMF %s (%d)%s '%s'", op, n, hstr, str);
}
#endif

static ngx_int_t
ngx_amf_get(ngx_amf_ctx_t *ctx, void *p, size_t n)
{
    u_char       *pos, *last;
    size_t        size, offset;
    ngx_chain_t  *l;
#ifdef NGX_DEBUG
    void         *op = p;
    size_t        on = n;
#endif

    if (!n) {
        return NGX_OK;
    }

    for (l = ctx->link, offset = ctx->offset; l; l = l->next, offset = 0) {

        pos  = l->buf->pos + offset;
        last = l->buf->last;

        if (last >= pos + n) {
            if (p) {
                p = ngx_cpymem(p, pos, n);
            }
            ctx->offset = offset + n;
            ctx->link = l;

#ifdef NGX_DEBUG
            ngx_amf_debug(ctx->log, "read", (u_char*)op, on);
#endif

            return NGX_OK;
        }

        size = last - pos;

        if (p) {
            p = ngx_cpymem(p, pos, size);
        }

        n -= size;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_CORE, ctx->log, 0,
                   "AMF read eof (%d)", n);

    return NGX_DONE;
}


static ngx_int_t
ngx_amf_read_object(ngx_amf_ctx_t *ctx, ngx_amf_elt_t *elts, size_t nelts)
{
    u_char     buf[2];
    size_t     n, namelen, maxlen;
    uint8_t    type;
    uint16_t   len;
    ngx_int_t  rc;

    maxlen = 0;
    for (n = 0; n < nelts; ++n) {
        namelen = elts[n].name.len;
        if (namelen > maxlen)
            maxlen = namelen;
    }

    for ( ;; ) {

#if !(NGX_WIN32)
        char    name[maxlen];
#else
        char    name[1024];
        if (maxlen > sizeof(name)) {
            return NGX_ERROR;
        }
#endif
        /* read key */
        switch (ngx_amf_get(ctx, buf, 2)) {
        case NGX_DONE:
            /* Envivio sends unfinalized arrays */
            return NGX_OK;
        case NGX_OK:
            break;
        default:
            return NGX_ERROR;
        }

        ngx_amf_reverse_copy(&len, buf, 2);

        if (!len) {
            break;
        }

        if (len <= maxlen) {
            rc = ngx_amf_get(ctx, name, len);

        } else {
            rc = ngx_amf_get(ctx, name, maxlen);
            if (rc != NGX_OK) {
                return NGX_ERROR;
            }

            rc = ngx_amf_get(ctx, 0, len - maxlen);
        }

        if (rc != NGX_OK) {
            return NGX_ERROR;
        }

        /* TODO: if we require array to be sorted on name
         * then we could be able to use binary search */
        for (n = 0; n < nelts
                    && (len != elts[n].name.len
                        || ngx_strncmp(name, elts[n].name.data, len));
             ++n);

        if (ngx_amf_read(ctx, n < nelts ? &elts[n] : NULL, 1) != NGX_OK) {
            return NGX_ERROR;
        }
    }

    if (ngx_amf_get(ctx, &type, 1) != NGX_OK || type != NGX_AMF_END) {
        return NGX_ERROR;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_amf_read_array(ngx_amf_ctx_t *ctx, ngx_amf_elt_t *elts, size_t nelts)
{
    u_char    buf[4];
    size_t    n;
    uint32_t  len;

    /* read length */
    if (ngx_amf_get(ctx, buf, 4) != NGX_OK) {
        return NGX_ERROR;
    }

    ngx_amf_reverse_copy(&len, buf, 4);

    for (n = 0; n < len; ++n) {
        if (ngx_amf_read(ctx, n < nelts ? &elts[n] : NULL, 1) != NGX_OK) {
            return NGX_ERROR;
        }
    }

    return NGX_OK;
}


static ngx_int_t
ngx_amf_read_variant(ngx_amf_ctx_t *ctx, ngx_amf_elt_t *elts, size_t nelts)
{
    size_t         n;
    uint8_t        type;
    ngx_int_t      rc;
    ngx_amf_elt_t  elt;

    rc = ngx_amf_get(ctx, &type, 1);
    if (rc != NGX_OK) {
        return rc;
    }

    ngx_memzero(&elt, sizeof(elt));
    for (n = 0; n < nelts; ++n, ++elts) {
        if (type == elts->type) {
            elt.data = elts->data;
            elt.len  = elts->len;
        }
    }

    elt.type = type | NGX_AMF_TYPELESS;

    return ngx_amf_read(ctx, &elt, 1);
}


static ngx_int_t
ngx_amf_is_compatible_type(uint8_t t1, uint8_t t2)
{
    return t1 == t2
           || (t1 == NGX_AMF_OBJECT && t2 == NGX_AMF_MIXED_ARRAY)
           || (t2 == NGX_AMF_OBJECT && t1 == NGX_AMF_MIXED_ARRAY);
}


static ngx_int_t
ngx_amf_read(ngx_amf_ctx_t *ctx, ngx_amf_elt_t *elts, size_t nelts)
{
    void       *data;
    u_char      buf[8];
    size_t      n;
    uint8_t     type8;
    uint16_t    len;
    uint32_t    max_index;
    ngx_int_t   type, rc;

    for (n = 0; n < nelts; ++n) {

        if (elts && elts->type & NGX_AMF_TYPELESS) {
            type = elts->type & ~NGX_AMF_TYPELESS;
            data = elts->data;

        } else {
            switch (ngx_amf_get(ctx, &type8, 1)) {
            case NGX_DONE:
                if (elts && elts->type & NGX_AMF_OPTIONAL) {
                    return NGX_OK;
                }
            case NGX_ERROR:
                return NGX_ERROR;
            }
            type = type8;
            data = (elts &&
                    ngx_amf_is_compatible_type((uint8_t) (elts->type & 0xff),
                                               (uint8_t) type))
                   ? elts->data
                   : NULL;

            if (elts && (elts->type & NGX_AMF_CONTEXT)) {
                if (data) {
                    *(ngx_amf_ctx_t *) data = *ctx;
                }
                data = NULL;
            }
        }

        switch (type) {
        case NGX_AMF_NUMBER:
            if (ngx_amf_get(ctx, buf, 8) != NGX_OK) {
                return NGX_ERROR;
            }
            ngx_amf_reverse_copy(data, buf, 8);
            break;

        case NGX_AMF_BOOLEAN:
            if (ngx_amf_get(ctx, data, 1) != NGX_OK) {
                return NGX_ERROR;
            }
            break;

        case NGX_AMF_STRING:
            if (ngx_amf_get(ctx, buf, 2) != NGX_OK) {
                return NGX_ERROR;
            }
            ngx_amf_reverse_copy(&len, buf, 2);

            if (data == NULL) {
                rc = ngx_amf_get(ctx, data, len);

            } else if (elts->len <= len) {
                rc = ngx_amf_get(ctx, data, elts->len - 1);
                if (rc != NGX_OK) {
                    return NGX_ERROR;
                }
                ((char*)data)[elts->len - 1] = 0;
                rc = ngx_amf_get(ctx, NULL, len - elts->len + 1);

            } else {
                rc = ngx_amf_get(ctx, data, len);
                ((char*)data)[len] = 0;
            }

            if (rc != NGX_OK) {
                return NGX_ERROR;
            }

            break;

        case NGX_AMF_NULL:
        case NGX_AMF_ARRAY_NULL:
            break;

        case NGX_AMF_MIXED_ARRAY:
            if (ngx_amf_get(ctx, &max_index, 4) != NGX_OK) {
                return NGX_ERROR;
            }

        case NGX_AMF_OBJECT:
            if (ngx_amf_read_object(ctx, data,
                    data && elts ? elts->len / sizeof(ngx_amf_elt_t) : 0
            ) != NGX_OK)
            {
                return NGX_ERROR;
            }
            break;

        case NGX_AMF_ARRAY:
            if (ngx_amf_read_array(ctx, data,
                    data && elts ? elts->len / sizeof(ngx_amf_elt_t) : 0
            ) != NGX_OK)
            {
                return NGX_ERROR;
            }
            break;

        case NGX_AMF_VARIANT_:
            if (ngx_amf_read_variant(ctx, data,
                    data && elts ? elts->len / sizeof(ngx_amf_elt_t) : 0
            ) != NGX_OK)
            {
                return NGX_ERROR;
            }
            break;

        case NGX_AMF_INT8:
            if (ngx_amf_get(ctx, data, 1) != NGX_OK) {
                return NGX_ERROR;
            }
            break;

        case NGX_AMF_INT16:
            if (ngx_amf_get(ctx, buf, 2) != NGX_OK) {
                return NGX_ERROR;
            }
            ngx_amf_reverse_copy(data, buf, 2);
            break;

        case NGX_AMF_INT32:
            if (ngx_amf_get(ctx, buf, 4) != NGX_OK) {
                return NGX_ERROR;
            }
            ngx_amf_reverse_copy(data, buf, 4);
            break;

        case NGX_AMF_END:
            return NGX_OK;

        default:
            return NGX_ERROR;
        }

        if (elts) {
            ++elts;
        }
    }

    return NGX_OK;
}


static char *
ngx_http_flv(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_core_loc_conf_t  *clcf;

    clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
    clcf->handler = ngx_http_flv_handler;

    return NGX_CONF_OK;
}


static void *
ngx_http_flv_create_conf(ngx_conf_t *cf)
{
    ngx_http_flv_conf_t  *conf;

    conf = ngx_palloc(cf->pool, sizeof(ngx_http_flv_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    conf->buffer_size = NGX_CONF_UNSET_SIZE;
    conf->max_buffer_size = NGX_CONF_UNSET_SIZE;
    conf->time_shift = NGX_CONF_UNSET;

    return conf;
}


static char *
ngx_http_flv_merge_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_flv_conf_t *prev = parent;
    ngx_http_flv_conf_t *conf = child;

    ngx_conf_merge_size_value(conf->buffer_size, prev->buffer_size, 512 * 1024);
    ngx_conf_merge_size_value(conf->max_buffer_size, prev->max_buffer_size,
                              2 * 1024 * 1024);
    ngx_conf_merge_value(conf->time_shift, prev->time_shift, 0);

    return NGX_CONF_OK;
}
