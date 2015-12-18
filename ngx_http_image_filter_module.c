
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_event.h>

#include <gd.h>

#include <webp/encode.h>
#include <webp/decode.h>

#define NGX_HTTP_IMAGE_OFF       0
#define NGX_HTTP_IMAGE_TEST      1
#define NGX_HTTP_IMAGE_SIZE      2
#define NGX_HTTP_IMAGE_RESIZE    3
#define NGX_HTTP_IMAGE_CROP      4
#define NGX_HTTP_IMAGE_ROTATE    5


#define NGX_HTTP_IMAGE_START     0
#define NGX_HTTP_IMAGE_READ      1
#define NGX_HTTP_IMAGE_PROCESS   2
#define NGX_HTTP_IMAGE_PASS      3
#define NGX_HTTP_IMAGE_DONE      4


#define NGX_HTTP_IMAGE_NONE      0
#define NGX_HTTP_IMAGE_JPEG      1
#define NGX_HTTP_IMAGE_GIF       2
#define NGX_HTTP_IMAGE_PNG       3
#define NGX_HTTP_IMAGE_WEBP      4


#define NGX_HTTP_IMAGE_BUFFERED  0x08


typedef struct {
    ngx_uint_t                   filter;
    ngx_uint_t                   width;
    ngx_uint_t                   height;
    ngx_uint_t                   angle;
    ngx_uint_t                   jpeg_quality;
    ngx_uint_t                   sharpen;

    ngx_str_t                    cache_path;

    ngx_flag_t                   transparency;
    ngx_flag_t                   save_cache;
    ngx_flag_t                   lookup_cache;

    ngx_http_complex_value_t    *wcv;
    ngx_http_complex_value_t    *hcv;
    ngx_http_complex_value_t    *acv;
    ngx_http_complex_value_t    *jqcv;
    ngx_http_complex_value_t    *shcv;

    size_t                       buffer_size;
} ngx_http_image_filter_conf_t;


typedef struct {
    u_char                      *image;
    u_char                      *last;
    WebPPicture                  pic;

    size_t                       length;

    ngx_uint_t                   width;
    ngx_uint_t                   height;
    ngx_uint_t                   max_width;
    ngx_uint_t                   max_height;
    ngx_uint_t                   angle;

    ngx_uint_t                   phase;
    ngx_uint_t                   type;
    ngx_uint_t                   force;
} ngx_http_image_filter_ctx_t;


static ngx_int_t ngx_http_image_send(ngx_http_request_t *r,
    ngx_http_image_filter_ctx_t *ctx, ngx_chain_t *in);
static ngx_uint_t ngx_http_image_test(ngx_http_request_t *r, ngx_chain_t *in);
static ngx_int_t ngx_http_image_read(ngx_http_request_t *r, ngx_chain_t *in);
static ngx_buf_t *ngx_http_image_process(ngx_http_request_t *r);
static ngx_buf_t *ngx_http_image_json(ngx_http_request_t *r,
    ngx_http_image_filter_ctx_t *ctx);
static ngx_buf_t *ngx_http_image_asis(ngx_http_request_t *r,
    ngx_http_image_filter_ctx_t *ctx);
static void ngx_http_image_length(ngx_http_request_t *r, ngx_buf_t *b);
static ngx_int_t ngx_http_image_size(ngx_http_request_t *r,
    ngx_http_image_filter_ctx_t *ctx);

static ngx_buf_t *ngx_http_image_resize(ngx_http_request_t *r,
    ngx_http_image_filter_ctx_t *ctx);
static gdImagePtr ngx_http_image_source(ngx_http_request_t *r,
    ngx_http_image_filter_ctx_t *ctx);
static gdImagePtr ngx_http_image_new(ngx_http_request_t *r, int w, int h,
    int colors);
static u_char *ngx_http_image_out(ngx_http_request_t *r, ngx_uint_t type,
    gdImagePtr img, int *size);
static void ngx_http_image_cleanup(void *data);
static void ngx_http_image_webp_cleanup(void *data);
static ngx_uint_t ngx_http_image_filter_get_value(ngx_http_request_t *r,
    ngx_http_complex_value_t *cv, ngx_uint_t v);
static ngx_uint_t ngx_http_image_filter_value(ngx_str_t *value);


static void *ngx_http_image_filter_create_conf(ngx_conf_t *cf);
static char *ngx_http_image_filter_merge_conf(ngx_conf_t *cf, void *parent,
    void *child);
static char *ngx_http_image_filter(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static char *ngx_http_image_filter_jpeg_quality(ngx_conf_t *cf,
    ngx_command_t *cmd, void *conf);
static char *ngx_http_image_filter_sharpen(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static ngx_int_t ngx_http_image_filter_init(ngx_conf_t *cf);


static ngx_command_t  ngx_http_image_filter_commands[] = {

    { ngx_string("image_filter"),
      NGX_HTTP_LOC_CONF|NGX_CONF_TAKE123,
      ngx_http_image_filter,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("image_filter_jpeg_quality"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_http_image_filter_jpeg_quality,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("image_filter_sharpen"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_http_image_filter_sharpen,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("image_filter_transparency"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_image_filter_conf_t, transparency),
      NULL },

	{ ngx_string("image_filter_save_cache"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_image_filter_conf_t, save_cache),
      NULL },

	{ ngx_string("image_filter_lookup_cache"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_image_filter_conf_t, lookup_cache),
      NULL },

    { ngx_string("image_filter_cache_path"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_image_filter_conf_t, cache_path),
      NULL },

    { ngx_string("image_filter_buffer"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_image_filter_conf_t, buffer_size),
      NULL },

      ngx_null_command
};


static ngx_http_module_t  ngx_http_image_filter_module_ctx = {
    NULL,                                  /* preconfiguration */
    ngx_http_image_filter_init,            /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    ngx_http_image_filter_create_conf,     /* create location configuration */
    ngx_http_image_filter_merge_conf       /* merge location configuration */
};


ngx_module_t  ngx_http_image_filter_module = {
    NGX_MODULE_V1,
    &ngx_http_image_filter_module_ctx,     /* module context */
    ngx_http_image_filter_commands,        /* module directives */
    NGX_HTTP_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};


static ngx_http_output_header_filter_pt  ngx_http_next_header_filter;
static ngx_http_output_body_filter_pt    ngx_http_next_body_filter;


static ngx_str_t  ngx_http_image_types[] = {
    ngx_string("image/jpeg"),
    ngx_string("image/gif"),
    ngx_string("image/png"),
    ngx_string("image/webp")
};


static ngx_int_t
ngx_http_image_header_filter(ngx_http_request_t *r)
{
    off_t                          len;
    ngx_http_image_filter_ctx_t   *ctx;
    ngx_http_image_filter_conf_t  *conf;

    if (r->headers_out.status == NGX_HTTP_NOT_MODIFIED) {
        return ngx_http_next_header_filter(r);
    }

    ctx = ngx_http_get_module_ctx(r, ngx_http_image_filter_module);

    if (ctx) {
        ngx_http_set_ctx(r, NULL, ngx_http_image_filter_module);
        return ngx_http_next_header_filter(r);
    }

    conf = ngx_http_get_module_loc_conf(r, ngx_http_image_filter_module);

    if (conf->filter == NGX_HTTP_IMAGE_OFF) {
        return ngx_http_next_header_filter(r);
    }

    if (r->headers_out.content_type.len
            >= sizeof("multipart/x-mixed-replace") - 1
        && ngx_strncasecmp(r->headers_out.content_type.data,
                           (u_char *) "multipart/x-mixed-replace",
                           sizeof("multipart/x-mixed-replace") - 1)
           == 0)
    {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "image filter: multipart/x-mixed-replace response");

        return NGX_ERROR;
    }

    ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_image_filter_ctx_t));
    if (ctx == NULL) {
        return NGX_ERROR;
    }

    ngx_http_set_ctx(r, ctx, ngx_http_image_filter_module);

    len = r->headers_out.content_length_n;

    if (len != -1 && len > (off_t) conf->buffer_size) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "image filter: too big response: %O", len);

        return NGX_HTTP_UNSUPPORTED_MEDIA_TYPE;
    }

    if (len == -1) {
        ctx->length = conf->buffer_size;

    } else {
        ctx->length = (size_t) len;
    }

    if (r->headers_out.refresh) {
        r->headers_out.refresh->hash = 0;
    }

    r->main_filter_need_in_memory = 1;
    r->allow_ranges = 0;

    return NGX_OK;
}

extern int            ngx_eventfd;
extern aio_context_t  ngx_aio_ctx;


static void ngx_file_aio_event_handler(ngx_event_t *ev);


static int
io_submit(aio_context_t ctx, long n, struct iocb **paiocb)
{
    return syscall(SYS_io_submit, ctx, n, paiocb);
}


ssize_t
ngx_file_aio_write(ngx_file_t *file, u_char *buf, size_t size, off_t offset,
    ngx_pool_t *pool)
{
    ngx_err_t         err;
    struct iocb      *piocb[1];
    ngx_event_t      *ev;
    ngx_event_aio_t  *aio;

    if (!ngx_file_aio) {
        return ngx_write_file(file, buf, size, offset);
    }

    aio = file->aio;

    if (aio == NULL) {
        aio = ngx_pcalloc(pool, sizeof(ngx_event_aio_t));
        if (aio == NULL) {
            return NGX_ERROR;
        }

        aio->file = file;
        aio->fd = file->fd;
        aio->event.data = aio;
        aio->event.ready = 1;
        aio->event.log = file->log;
        file->aio = aio;
    }

    ev = &aio->event;

    if (!ev->ready) {
        ngx_log_error(NGX_LOG_ALERT, file->log, 0,
                      "second aio post for \"%V\"", &file->name);
        return NGX_AGAIN;
    }

    ngx_log_debug4(NGX_LOG_DEBUG_CORE, file->log, 0,
                   "aio complete:%d @%O:%z %V",
                   ev->complete, offset, size, &file->name);

    if (ev->complete) {
        ev->active = 0;
        ev->complete = 0;

        if (aio->res >= 0) {
            ngx_set_errno(0);
            return aio->res;
        }

        ngx_set_errno(-aio->res);

        ngx_log_error(NGX_LOG_CRIT, file->log, ngx_errno,
                      "aio write \"%s\" failed", file->name.data);

        return NGX_ERROR;
    }

    ngx_memzero(&aio->aiocb, sizeof(struct iocb));

    aio->aiocb.aio_data = (uint64_t) (uintptr_t) ev;
    aio->aiocb.aio_lio_opcode = IOCB_CMD_PWRITE;
    aio->aiocb.aio_fildes = file->fd;
    aio->aiocb.aio_buf = (uint64_t) (uintptr_t) buf;
    aio->aiocb.aio_nbytes = size;
    aio->aiocb.aio_offset = offset;
    aio->aiocb.aio_flags = IOCB_FLAG_RESFD;
    aio->aiocb.aio_resfd = ngx_eventfd;

    ev->handler = ngx_file_aio_event_handler;

    piocb[0] = &aio->aiocb;

    if (io_submit(ngx_aio_ctx, 1, piocb) == 1) {
        ev->active = 1;
        ev->ready = 0;
        ev->complete = 0;

        return NGX_AGAIN;
    }

    err = ngx_errno;

    if (err == NGX_EAGAIN) {
        return ngx_write_file(file, buf, size, offset);
    }

    ngx_log_error(NGX_LOG_CRIT, file->log, err,
                  "io_submit(\"%V\") failed", &file->name);

    if (err == NGX_ENOSYS) {
        ngx_file_aio = 0;
        return ngx_write_file(file, buf, size, offset);
    }

    return NGX_ERROR;
}


static void
ngx_file_aio_event_handler(ngx_event_t *ev)
{
    ngx_event_aio_t  *aio;

    aio = ev->data;

    ngx_log_debug2(NGX_LOG_DEBUG_CORE, ev->log, 0,
                   "aio event handler fd:%d %V", aio->fd, &aio->file->name);

    aio->handler(ev);
}

struct image_cache_s {
	u_char file_name[128];
	int name_len;
	ngx_file_t file;
	u_char *buf;
	ngx_log_t log;
	ngx_open_file_t log_file;
	ngx_event_aio_t aio;
};

typedef struct image_cache_s image_cache_t;

static void
ngx_http_save_cache_file_handler(ngx_event_t *ev)
{
	image_cache_t *im;
	u_char new_name[128];
	im = ((ngx_event_aio_t *)ev->data)->data;
	
	if(ngx_close_file(im->file.fd) == NGX_FILE_ERROR){
		ngx_log_error(NGX_LOG_ALERT,ev->log,ngx_errno,ngx_close_file_n " \"%s\" failed",im->file_name);
	}
	ngx_memzero(new_name,128);
	ngx_memcpy(new_name,im->file_name,im->name_len);
	if(ngx_rename_file(im->file_name,new_name) == NGX_FILE_ERROR){
		ngx_log_error(NGX_LOG_ERR, ev->log, ngx_errno, "\"%s\"",im->file_name);
	}
	
	//ngx_log_error(NGX_LOG_ERR, ev->log, 0, "\"%s\",\"%s\"",im->file_name,new_name);
	free(im->buf);
    free(im);
}

static ngx_int_t
ngx_http_save_cache_file(ngx_http_request_t *r, ngx_chain_t *in,ngx_chain_t *out)
{
	u_char *uri_file_name;
    int index = 0;
	size_t file_len;
	int rand_stamp;
	image_cache_t *im;
	ngx_int_t result;
    ngx_http_image_filter_conf_t  *conf;

    conf = ngx_http_get_module_loc_conf(r, ngx_http_image_filter_module);

	im = calloc(1,sizeof(image_cache_t));
	if(im == NULL){
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "\"%d\" :can't malloc space",__LINE__);
		return NGX_ERROR;
	}

	/*uri_start plus 12 than point to file_name*/
	im->name_len = r->uri_end - r->uri_start;
	uri_file_name = r->uri_start;

	/*doesn't exist temp file*/
	do{
		rand_stamp = rand()%1000000;
		snprintf((char *)im->file_name,128,"%.*s%.*s-%d",(int)conf->cache_path.len,conf->cache_path.data,im->name_len,uri_file_name,rand_stamp);
	}while(access((char *)im->file_name,F_OK) == 0);

    /*strlen("/data/imagecache/") = 17*/
	//ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "\"%s\"",im->file_name);
    index = conf->cache_path.len;
	im->name_len += conf->cache_path.len;
    /*create path*/
    while(1){
        if(index == im->name_len) 
            break;
		//ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "\"%c\"\"%d\"",im->file_name[index],index);
        if(im->file_name[index] != '/') {
            index++;
            continue;
        }
        im->file_name[index] = 0;
	    if(access((char*)im->file_name,F_OK) != 0) {
            if (ngx_create_dir(im->file_name, S_IRWXU) == NGX_FILE_ERROR) {
			    ngx_log_error(NGX_LOG_ERR, r->connection->log, ngx_errno, "create \"%s\" failed",im->file_name);
                free(im);
                return NGX_ERROR;
		    }
        }
        im->file_name[index] = '/';
        index++;
    }

	im->file.fd = ngx_open_file(im->file_name, NGX_FILE_WRONLY|NGX_FILE_NONBLOCK, NGX_FILE_CREATE_OR_OPEN,NGX_FILE_DEFAULT_ACCESS);

	if(im->file.fd <= 0){
		ngx_log_error(NGX_LOG_ERR, r->connection->log, ngx_errno, "can't open file \"%s\"",im->file_name);
		free(im);
		return NGX_ERROR;
	}
	file_len = out->buf->last - out->buf->pos;
	im->buf = malloc(file_len);
	if(im->buf == NULL){
		free(im);
		ngx_log_error(NGX_LOG_ERR, r->connection->log, ngx_errno, "\"%d\" :can't malloc space",__LINE__);
		return NGX_ERROR;
	}
	ngx_memcpy(im->buf,out->buf->pos,file_len);

    im->file.aio = &im->aio;

	im->log.file = &im->log_file;
	im->log.log_level = NGX_LOG_DEBUG;
	im->log_file.fd = r->connection->log->file->fd;

    im->file.aio->file = &im->file;
    im->file.aio->fd = im->file.fd;
	im->file.aio->event.data = &im->aio;
    im->file.aio->event.ready = 1;
	im->file.aio->data = im;
	im->file.log = &im->log;
    im->file.aio->event.log = im->file.log;
#if (NGX_HAVE_AIO_SENDFILE)
    im->file.aio->last_offset = -1;
#endif
	im->file.aio->handler = ngx_http_save_cache_file_handler;
	if((result = ngx_file_aio_write(&im->file,im->buf,file_len,0,r->pool)) != NGX_AGAIN){
		free(im->buf);
		free(im);
		return result;
	}
	return NGX_OK;
}


static ngx_int_t
ngx_http_lookup_cache_file(ngx_http_request_t *r, ngx_chain_t *in,ngx_chain_t *out)
{
    u_char buf[128];
    u_char file_name[128];
    ngx_buf_t *b;
	ngx_pool_cleanup_t *cln;
	size_t name_len;
	u_char *uri_file_name;
    ngx_http_image_filter_conf_t  *conf;

    conf = ngx_http_get_module_loc_conf(r, ngx_http_image_filter_module);
	
    memset(buf, 0, 128);
    memset(file_name, 0, 128);
    memcpy(file_name, conf->cache_path.data, conf->cache_path.len);
	name_len = r->uri_end - r->uri_start;
    memcpy(buf,r->uri_start,name_len);
	uri_file_name = buf;

	strncat((char*)file_name,(char *)uri_file_name,128);
    //ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "\"%s\"\n",file_name);

    if(access((char *)file_name,F_OK) == 0) {

		b = ngx_palloc(r->pool, sizeof(ngx_buf_t));
		ngx_memzero(b,sizeof(ngx_buf_t));
		b->in_file = 1;
		b->file = ngx_palloc(r->pool, sizeof(ngx_file_t));
		ngx_memzero(b->file,sizeof(ngx_file_t));
		b->file->fd = ngx_open_file(file_name,NGX_FILE_RDONLY|NGX_FILE_NONBLOCK, NGX_FILE_OPEN, 0);

		b->file->log = r->connection->log;
	
		if(b->file->fd <= 0){
			ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "can't find\n");
			return NGX_HTTP_NOT_FOUND;
		}

		if(ngx_file_info(file_name,&b->file->info) == NGX_FILE_ERROR){
			return ngx_http_filter_finalize_request(r,
                                              &ngx_http_image_filter_module,
											  NGX_HTTP_INTERNAL_SERVER_ERROR);
		}

		if(b->file->info.st_size < 128)
			return NGX_HTTP_NOT_FOUND;
		r->connection->buffered &= ~NGX_HTTP_IMAGE_BUFFERED;
		r->headers_out.content_length_n = b->file->info.st_size;
		if (r->headers_out.content_length) {
			r->headers_out.content_length->hash = 0;
		}

		r->headers_out.content_length = NULL;

		b->file_pos = 0;
		b->file_last = b->file->info.st_size;
		b->last_buf = 1;

		out->buf = b;
		out->next = NULL;
	
		cln = ngx_pool_cleanup_add(r->pool, sizeof(ngx_pool_cleanup_file_t));
		if(cln == NULL){
			return ngx_http_filter_finalize_request(r,
                                              &ngx_http_image_filter_module,
											  NGX_ERROR);
		}
		cln->handler = ngx_pool_cleanup_file;
		ngx_pool_cleanup_file_t *clnf = cln->data;

		clnf->fd = b->file->fd;
		clnf->log = r->pool->log;

		return NGX_OK; 
    }

	//ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "can't find 2\n");
	return NGX_HTTP_NOT_FOUND;
}

/*static ngx_int_t
ngx_image_cache_mkdir(const char * path,ngx_log_t *log)
{
	char path_buf[128];
	int first_dir,second_dir;
	char first_dir_buf[8],second_dir_buf[8];
	mode_t old_mask;

	old_mask = umask(0);
	snprintf(path_buf,128,"%s/%s",path,"mkdir_done");
	if(access(path,F_OK) == 0){
		if(access(path_buf,F_OK) == 0)
			return NGX_OK;
	}else{
		ngx_log_error(NGX_LOG_ERR, log, ngx_errno, "cache path :\"%s\" doesn't exist",path);
		return NGX_ERROR;
	}
	for(first_dir = 0;first_dir != 256;++first_dir){
		snprintf(first_dir_buf,8,"%02X",first_dir);
		snprintf(path_buf,128,"%s/%s",path,first_dir_buf);
		if (ngx_create_dir(path_buf, S_IRWXU|S_IRWXG|S_IRWXO) == NGX_FILE_ERROR) {
			ngx_log_error(NGX_LOG_ERR, log, ngx_errno, "create \"%s\" failed",path_buf);
		}
		for(second_dir = 0;second_dir != 256;++second_dir){
			snprintf(second_dir_buf,8,"%02X",second_dir);
			snprintf(path_buf,128,"%s/%s/%s",path,first_dir_buf,second_dir_buf);
			if (ngx_create_dir(path_buf, S_IRWXU|S_IRWXG|S_IRWXO|S_IWOTH) == NGX_FILE_ERROR) {
				ngx_log_error(NGX_LOG_ERR, log, ngx_errno, "create \"%s\" failed",path_buf);
			}
		}
	}
	snprintf(path_buf,128,"%s/%s",path,"mkdir_done");
	if (ngx_create_dir(path_buf, S_IRWXU|S_IRWXG|S_IRWXO) == NGX_FILE_ERROR) {
		ngx_log_error(NGX_LOG_ERR, log, ngx_errno, "create \"%s\" failed",path_buf);
	}
	umask(old_mask);

	return NGX_OK;
}*/

int ExUtilLoadWebP(const uint8_t* data, size_t data_size,
                   WebPBitstreamFeatures* bitstream) {
  VP8StatusCode status;
  WebPBitstreamFeatures local_features;

  if (bitstream == NULL) {
    bitstream = &local_features;
  }

  status = WebPGetFeatures(data, data_size, bitstream);
  if (status != VP8_STATUS_OK) {
    return 0;
  }
  return 1;
}

VP8StatusCode ExUtilDecodeWebP(const uint8_t* const data, size_t data_size,
                               int verbose, WebPDecoderConfig* const config) {
  VP8StatusCode status = VP8_STATUS_OK;
  if (config == NULL) return VP8_STATUS_INVALID_PARAM;

  // Decoding call.
  status = WebPDecode(data, data_size, config);

  return status;
}

int ReadWebP(const uint8_t* data, size_t data_size, WebPPicture* const pic, int keep_alpha)  
{
  int ok = 0;
  VP8StatusCode status = VP8_STATUS_OK;
  WebPDecoderConfig config;
  WebPDecBuffer* const output_buffer = &config.output;
  WebPBitstreamFeatures* const bitstream = &config.input;

  if (!WebPInitDecoderConfig(&config)) {
    return 0;
  }

  if (ExUtilLoadWebP(data, data_size, bitstream)) {
    const int has_alpha = keep_alpha && bitstream->has_alpha;
    output_buffer->colorspace = has_alpha ? MODE_RGBA : MODE_RGB;

    status = ExUtilDecodeWebP(data, data_size, 0, &config);
    if (status == VP8_STATUS_OK) {
      const uint8_t* const rgba = output_buffer->u.RGBA.rgba;
      const int stride = output_buffer->u.RGBA.stride;
      pic->width = output_buffer->width;
      pic->height = output_buffer->height;
      pic->use_argb = 1;
      ok = has_alpha ? WebPPictureImportRGBA(pic, rgba, stride)
                     : WebPPictureImportRGB(pic, rgba, stride);
    }
  }

  WebPFreeDecBuffer(output_buffer);
  return ok;
}

static ngx_int_t
ngx_http_image_body_filter(ngx_http_request_t *r, ngx_chain_t *in)
{
    ngx_int_t                      rc;
    ngx_str_t                     *ct;
    ngx_chain_t                    out;
    ngx_http_image_filter_ctx_t   *ctx;
    ngx_http_image_filter_conf_t  *conf;
	ngx_int_t					  status;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "image filter");

    if (in == NULL) {
        return ngx_http_next_body_filter(r, in);
    }

    ctx = ngx_http_get_module_ctx(r, ngx_http_image_filter_module);

    if (ctx == NULL) {
        return ngx_http_next_body_filter(r, in);
    }

    switch (ctx->phase) {

    case NGX_HTTP_IMAGE_START:

        ctx->type = ngx_http_image_test(r, in);

        conf = ngx_http_get_module_loc_conf(r, ngx_http_image_filter_module);

        if (ctx->type == NGX_HTTP_IMAGE_NONE) {

            if (conf->filter == NGX_HTTP_IMAGE_SIZE) {
                out.buf = ngx_http_image_json(r, NULL);

                if (out.buf) {
                    out.next = NULL;
                    ctx->phase = NGX_HTTP_IMAGE_DONE;

                    return ngx_http_image_send(r, ctx, &out);
                }
            }

	    if(in->buf->last == in->buf->pos)
		return NGX_OK;
            return ngx_http_filter_finalize_request(r,
                                              &ngx_http_image_filter_module,
                                              NGX_HTTP_UNSUPPORTED_MEDIA_TYPE);
        }

        /* override content type */

        ct = &ngx_http_image_types[ctx->type - 1];
        r->headers_out.content_type_len = ct->len;
        r->headers_out.content_type = *ct;
        r->headers_out.content_type_lowcase = NULL;

        if (conf->filter == NGX_HTTP_IMAGE_TEST) {
            ctx->phase = NGX_HTTP_IMAGE_PASS;

            return ngx_http_image_send(r, ctx, in);
        }

        ctx->phase = NGX_HTTP_IMAGE_READ;

        /* fall through */

    case NGX_HTTP_IMAGE_READ:

        rc = ngx_http_image_read(r, in);

        if (rc == NGX_AGAIN) {
            return NGX_OK;
        }

        if (rc == NGX_ERROR) {
            return ngx_http_filter_finalize_request(r,
                                              &ngx_http_image_filter_module,
                                              NGX_HTTP_UNSUPPORTED_MEDIA_TYPE);
        }

        /* fall through */

    case NGX_HTTP_IMAGE_PROCESS:

        conf = ngx_http_get_module_loc_conf(r, ngx_http_image_filter_module);
		
		//ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "\"%d\":\"%d\"",conf->lookup_cache,conf->save_cache);
		if(conf->lookup_cache){
			status = ngx_http_lookup_cache_file(r,in,&out);

			if(status == NGX_OK){
				ctx->phase = NGX_HTTP_IMAGE_PASS;
				return ngx_http_image_send(r,ctx,&out);
			}
		}

        out.buf = ngx_http_image_process(r);

        if(ctx->type == NGX_HTTP_IMAGE_WEBP)
            WebPPictureFree(&ctx->pic);

        if (out.buf == NULL) {
            return ngx_http_filter_finalize_request(r,
                                              &ngx_http_image_filter_module,
                                              NGX_HTTP_UNSUPPORTED_MEDIA_TYPE);
        }

        out.next = NULL;
        ctx->phase = NGX_HTTP_IMAGE_PASS;

		if(conf->save_cache){
			ngx_http_save_cache_file(r,in,&out);
		}
        return ngx_http_image_send(r, ctx, &out);

    case NGX_HTTP_IMAGE_PASS:

        return ngx_http_next_body_filter(r, in);

    default: /* NGX_HTTP_IMAGE_DONE */

        rc = ngx_http_next_body_filter(r, NULL);

        /* NGX_ERROR resets any pending data */
        return (rc == NGX_OK) ? NGX_ERROR : rc;
    }
}


static ngx_int_t
ngx_http_image_send(ngx_http_request_t *r, ngx_http_image_filter_ctx_t *ctx,
    ngx_chain_t *in)
{
    ngx_int_t  rc;

    rc = ngx_http_next_header_filter(r);

    if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
        return NGX_ERROR;
    }

    rc = ngx_http_next_body_filter(r, in);

    if (ctx->phase == NGX_HTTP_IMAGE_DONE) {
        /* NGX_ERROR resets any pending data */
        return (rc == NGX_OK) ? NGX_ERROR : rc;
    }

    return rc;
}


static ngx_uint_t
ngx_http_image_test(ngx_http_request_t *r, ngx_chain_t *in)
{
    u_char  *p;

    p = in->buf->pos;

    if (in->buf->last - p < 16) {
        return NGX_HTTP_IMAGE_NONE;
    }

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "image filter: \"%c%c\"", p[0], p[1]);

    if (p[0] == 0xff && p[1] == 0xd8) {

        /* JPEG */

        return NGX_HTTP_IMAGE_JPEG;

    } else if (p[0] == 'G' && p[1] == 'I' && p[2] == 'F' && p[3] == '8'
               && p[5] == 'a')
    {
        if (p[4] == '9' || p[4] == '7') {
            /* GIF */
            return NGX_HTTP_IMAGE_GIF;
        }

    } else if (p[0] == 0x89 && p[1] == 'P' && p[2] == 'N' && p[3] == 'G'
               && p[4] == 0x0d && p[5] == 0x0a && p[6] == 0x1a && p[7] == 0x0a)
    {
        /* PNG */

        return NGX_HTTP_IMAGE_PNG;
    }
    uint32_t webp_magic1 = ((uint32_t)p[0] << 24) | (p[1] << 16) | (p[2] << 8) | p[3];
    uint32_t webp_magic2 = ((uint32_t)p[8] << 24) | (p[9] << 16) | (p[10] << 8) | p[11];

    if (webp_magic1 == 0x52494646 && webp_magic2 == 0x57454250)
        return NGX_HTTP_IMAGE_WEBP;



    return NGX_HTTP_IMAGE_NONE;
}


static ngx_int_t
ngx_http_image_read(ngx_http_request_t *r, ngx_chain_t *in)
{
    u_char                       *p;
    size_t                        size, rest;
    ngx_buf_t                    *b;
    ngx_chain_t                  *cl;
    ngx_http_image_filter_ctx_t  *ctx;

    ctx = ngx_http_get_module_ctx(r, ngx_http_image_filter_module);

    if (ctx->image == NULL) {
        ctx->image = ngx_palloc(r->pool, ctx->length);
        if (ctx->image == NULL) {
            return NGX_ERROR;
        }

        ctx->last = ctx->image;
    }

    p = ctx->last;

    for (cl = in; cl; cl = cl->next) {

        b = cl->buf;
        size = b->last - b->pos;

        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "image buf: %uz", size);

        rest = ctx->image + ctx->length - p;
        size = (rest < size) ? rest : size;

        p = ngx_cpymem(p, b->pos, size);
        b->pos += size;

        if (b->last_buf) {
            ctx->last = p;
            return NGX_OK;
        }
    }

    ctx->last = p;
    r->connection->buffered |= NGX_HTTP_IMAGE_BUFFERED;

    return NGX_AGAIN;
}


static ngx_buf_t *
ngx_http_image_process(ngx_http_request_t *r)
{
    ngx_int_t                      rc;
    ngx_http_image_filter_ctx_t   *ctx;
    ngx_http_image_filter_conf_t  *conf;

    r->connection->buffered &= ~NGX_HTTP_IMAGE_BUFFERED;

    ctx = ngx_http_get_module_ctx(r, ngx_http_image_filter_module);

    rc = ngx_http_image_size(r, ctx);

    conf = ngx_http_get_module_loc_conf(r, ngx_http_image_filter_module);

    if (conf->filter == NGX_HTTP_IMAGE_SIZE) {
        return ngx_http_image_json(r, rc == NGX_OK ? ctx : NULL);
    }

    ctx->angle = ngx_http_image_filter_get_value(r, conf->acv, conf->angle);

    if (conf->filter == NGX_HTTP_IMAGE_ROTATE) {

        if (ctx->angle != 90 && ctx->angle != 180 && ctx->angle != 270) {
            return NULL;
        }

        return ngx_http_image_resize(r, ctx);
    }

    ctx->max_width = ngx_http_image_filter_get_value(r, conf->wcv, conf->width);
    if (ctx->max_width == 0) {
        return NULL;
    }

    ctx->max_height = ngx_http_image_filter_get_value(r, conf->hcv,
                                                      conf->height);
    if (ctx->max_height == 0) {
        return NULL;
    }

    if (rc == NGX_OK
        && ctx->width <= ctx->max_width
        && ctx->height <= ctx->max_height
        && ctx->angle == 0
        && !ctx->force)
    {
        return ngx_http_image_asis(r, ctx);
    }

    return ngx_http_image_resize(r, ctx);
}


static ngx_buf_t *
ngx_http_image_json(ngx_http_request_t *r, ngx_http_image_filter_ctx_t *ctx)
{
    size_t      len;
    ngx_buf_t  *b;

    b = ngx_pcalloc(r->pool, sizeof(ngx_buf_t));
    if (b == NULL) {
        return NULL;
    }

    b->memory = 1;
    b->last_buf = 1;

    ngx_http_clean_header(r);

    r->headers_out.status = NGX_HTTP_OK;
    ngx_str_set(&r->headers_out.content_type, "text/plain");
    r->headers_out.content_type_lowcase = NULL;

    if (ctx == NULL) {
        b->pos = (u_char *) "{}" CRLF;
        b->last = b->pos + sizeof("{}" CRLF) - 1;

        ngx_http_image_length(r, b);

        return b;
    }

    len = sizeof("{ \"img\" : "
                 "{ \"width\": , \"height\": , \"type\": \"jpeg\" } }" CRLF) - 1
          + 2 * NGX_SIZE_T_LEN;

    b->pos = ngx_pnalloc(r->pool, len);
    if (b->pos == NULL) {
        return NULL;
    }

    b->last = ngx_sprintf(b->pos,
                          "{ \"img\" : "
                                       "{ \"width\": %uz,"
                                        " \"height\": %uz,"
                                        " \"type\": \"%s\" } }" CRLF,
                          ctx->width, ctx->height,
                          ngx_http_image_types[ctx->type - 1].data + 6);

    ngx_http_image_length(r, b);

    return b;
}


static ngx_buf_t *
ngx_http_image_asis(ngx_http_request_t *r, ngx_http_image_filter_ctx_t *ctx)
{
    ngx_buf_t  *b;

    b = ngx_pcalloc(r->pool, sizeof(ngx_buf_t));
    if (b == NULL) {
        return NULL;
    }

    b->pos = ctx->image;
    b->last = ctx->last;
    b->memory = 1;
    b->last_buf = 1;

    ngx_http_image_length(r, b);

    return b;
}


static void
ngx_http_image_length(ngx_http_request_t *r, ngx_buf_t *b)
{
    r->headers_out.content_length_n = b->last - b->pos;

    if (r->headers_out.content_length) {
        r->headers_out.content_length->hash = 0;
    }

    r->headers_out.content_length = NULL;
}


static ngx_int_t
ngx_http_image_size(ngx_http_request_t *r, ngx_http_image_filter_ctx_t *ctx)
{
    u_char      *p, *last;
    size_t       len, app;
    ngx_uint_t   width, height;

    p = ctx->image;

    switch (ctx->type) {

    case NGX_HTTP_IMAGE_JPEG:

        p += 2;
        last = ctx->image + ctx->length - 10;
        width = 0;
        height = 0;
        app = 0;

        while (p < last) {

            if (p[0] == 0xff && p[1] != 0xff) {

                ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                               "JPEG: %02xd %02xd", p[0], p[1]);

                p++;

                if ((*p == 0xc0 || *p == 0xc1 || *p == 0xc2 || *p == 0xc3
                     || *p == 0xc9 || *p == 0xca || *p == 0xcb)
                    && (width == 0 || height == 0))
                {
                    width = p[6] * 256 + p[7];
                    height = p[4] * 256 + p[5];
                }

                ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                               "JPEG: %02xd %02xd", p[1], p[2]);

                len = p[1] * 256 + p[2];

                if (*p >= 0xe1 && *p <= 0xef) {
                    /* application data, e.g., EXIF, Adobe XMP, etc. */
                    app += len;
                }

                p += len;

                continue;
            }

            p++;
        }

        if (width == 0 || height == 0) {
            return NGX_DECLINED;
        }

        if (ctx->length / 20 < app) {
            /* force conversion if application data consume more than 5% */
            ctx->force = 1;
            ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "app data size: %uz", app);
        }

        break;

    case NGX_HTTP_IMAGE_GIF:

        if (ctx->length < 10) {
            return NGX_DECLINED;
        }

        width = p[7] * 256 + p[6];
        height = p[9] * 256 + p[8];

        break;

    case NGX_HTTP_IMAGE_PNG:

        if (ctx->length < 24) {
            return NGX_DECLINED;
        }

        width = p[18] * 256 + p[19];
        height = p[22] * 256 + p[23];

        break;

    case NGX_HTTP_IMAGE_WEBP:

        WebPPictureInit(&ctx->pic);

        ReadWebP(p, ctx->length, &ctx->pic, 1);
        width = ctx->pic.width;
        height = ctx->pic.height;

        break;

    default:

        return NGX_DECLINED;
    }

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "image size: %d x %d", width, height);

    ctx->width = width;
    ctx->height = height;

    return NGX_OK;
}


static ngx_buf_t *
ngx_http_image_resize(ngx_http_request_t *r, ngx_http_image_filter_ctx_t *ctx)
{
    int                            sx, sy, dx, dy, ox, oy, ax, ay, size,
                                   colors, palette, transparent, sharpen,
                                   red, green, blue, t;
    u_char                        *out;
    ngx_buf_t                     *b;
    ngx_uint_t                     resize;
    gdImagePtr                     src, dst;
    ngx_pool_cleanup_t            *cln;
    ngx_http_image_filter_conf_t  *conf;

    if(ctx->type == NGX_HTTP_IMAGE_WEBP) {
        WebPConfig config;
        WebPMemoryWriter writer;

        WebPConfigInit(&config);
        WebPMemoryWriterInit(&writer);

        if (!WebPValidateConfig(&config)) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Error! Invalid configuration.");
            return NULL;
        }

        ctx->pic.writer = WebPMemoryWrite;
        ctx->pic.custom_ptr = &writer;
        dx = ctx->width;
        dy = ctx->height;
        if ((ngx_uint_t) dx > ctx->max_width) {
            dy = dy * ctx->max_width / dx;
            dy = dy ? dy : 1;
            dx = ctx->max_width;
        }

        if ((ngx_uint_t) dy > ctx->max_height) {
            dx = dx * ctx->max_height / dy;
            dx = dx ? dx : 1;
            dy = ctx->max_height;
        }
        if (!WebPPictureRescale(&ctx->pic, dx, dy)) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Error! Cannot resize picture");
            return NULL;
        }
        if (!WebPEncode(&config, &ctx->pic)) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Error! Cannot encode picture as WebP");
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Error code: %d (%d)",ctx->pic.error_code, ctx->pic.error_code);
            return NULL;
        } 

        out = writer.mem;
        size = writer.size;
        cln = ngx_pool_cleanup_add(r->pool, 0);
        if (cln == NULL) {
            free(out);
            return NULL;
        }

        b = ngx_pcalloc(r->pool, sizeof(ngx_buf_t));
        if (b == NULL) {
            free(out);
            return NULL;
        }

        cln->handler = ngx_http_image_webp_cleanup;
        cln->data = out;

        b->pos = out;
        b->last = out + size;
        b->memory = 1;
        b->last_buf = 1;

        ngx_http_image_length(r, b);

        return b;
    }
    src = ngx_http_image_source(r, ctx);

    if (src == NULL) {
        return NULL;
    }

    sx = gdImageSX(src);
    sy = gdImageSY(src);

    conf = ngx_http_get_module_loc_conf(r, ngx_http_image_filter_module);

    if (!ctx->force
        && ctx->angle == 0
        && (ngx_uint_t) sx <= ctx->max_width
        && (ngx_uint_t) sy <= ctx->max_height)
    {
        gdImageDestroy(src);
        return ngx_http_image_asis(r, ctx);
    }

    colors = gdImageColorsTotal(src);

    if (colors && conf->transparency) {
        transparent = gdImageGetTransparent(src);

        if (transparent != -1) {
            palette = colors;
            red = gdImageRed(src, transparent);
            green = gdImageGreen(src, transparent);
            blue = gdImageBlue(src, transparent);

            goto transparent;
        }
    }

    palette = 0;
    transparent = -1;
    red = 0;
    green = 0;
    blue = 0;

transparent:

    gdImageColorTransparent(src, -1);

    dx = sx;
    dy = sy;

    if (conf->filter == NGX_HTTP_IMAGE_RESIZE) {

        if ((ngx_uint_t) dx > ctx->max_width) {
            dy = dy * ctx->max_width / dx;
            dy = dy ? dy : 1;
            dx = ctx->max_width;
        }

        if ((ngx_uint_t) dy > ctx->max_height) {
            dx = dx * ctx->max_height / dy;
            dx = dx ? dx : 1;
            dy = ctx->max_height;
        }

        resize = 1;

    } else if (conf->filter == NGX_HTTP_IMAGE_ROTATE) {

        resize = 0;

    } else { /* NGX_HTTP_IMAGE_CROP */

        resize = 0;

        if ((double) dx / dy < (double) ctx->max_width / ctx->max_height) {
            if ((ngx_uint_t) dx > ctx->max_width) {
                dy = dy * ctx->max_width / dx;
                dy = dy ? dy : 1;
                dx = ctx->max_width;
                resize = 1;
            }

        } else {
            if ((ngx_uint_t) dy > ctx->max_height) {
                dx = dx * ctx->max_height / dy;
                dx = dx ? dx : 1;
                dy = ctx->max_height;
                resize = 1;
            }
        }
    }

    if (resize) {
        dst = ngx_http_image_new(r, dx, dy, palette);
        if (dst == NULL) {
            gdImageDestroy(src);
            return NULL;
        }

        if (colors == 0) {
            gdImageSaveAlpha(dst, 1);
            gdImageAlphaBlending(dst, 0);
        }

        gdImageCopyResampled(dst, src, 0, 0, 0, 0, dx, dy, sx, sy);

        if (colors) {
            gdImageTrueColorToPalette(dst, 1, 256);
        }

        gdImageDestroy(src);

    } else {
        dst = src;
    }

    if (ctx->angle) {
        src = dst;

        ax = (dx % 2 == 0) ? 1 : 0;
        ay = (dy % 2 == 0) ? 1 : 0;

        switch (ctx->angle) {

        case 90:
        case 270:
            dst = ngx_http_image_new(r, dy, dx, palette);
            if (dst == NULL) {
                gdImageDestroy(src);
                return NULL;
            }
            if (ctx->angle == 90) {
                ox = dy / 2 + ay;
                oy = dx / 2 - ax;

            } else {
                ox = dy / 2 - ay;
                oy = dx / 2 + ax;
            }

            gdImageCopyRotated(dst, src, ox, oy, 0, 0,
                               dx + ax, dy + ay, ctx->angle);
            gdImageDestroy(src);

            t = dx;
            dx = dy;
            dy = t;
            break;

        case 180:
            dst = ngx_http_image_new(r, dx, dy, palette);
            if (dst == NULL) {
                gdImageDestroy(src);
                return NULL;
            }
            gdImageCopyRotated(dst, src, dx / 2 - ax, dy / 2 - ay, 0, 0,
                               dx + ax, dy + ay, ctx->angle);
            gdImageDestroy(src);
            break;
        }
    }

    if (conf->filter == NGX_HTTP_IMAGE_CROP) {

        src = dst;

        if ((ngx_uint_t) dx > ctx->max_width) {
            ox = dx - ctx->max_width;

        } else {
            ox = 0;
        }

        if ((ngx_uint_t) dy > ctx->max_height) {
            oy = dy - ctx->max_height;

        } else {
            oy = 0;
        }

        if (ox || oy) {

            dst = ngx_http_image_new(r, dx - ox, dy - oy, colors);

            if (dst == NULL) {
                gdImageDestroy(src);
                return NULL;
            }

            ox /= 2;
            oy /= 2;

            ngx_log_debug4(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "image crop: %d x %d @ %d x %d",
                           dx, dy, ox, oy);

            if (colors == 0) {
                gdImageSaveAlpha(dst, 1);
                gdImageAlphaBlending(dst, 0);
            }

            gdImageCopy(dst, src, 0, 0, ox, oy, dx - ox, dy - oy);

            if (colors) {
                gdImageTrueColorToPalette(dst, 1, 256);
            }

            gdImageDestroy(src);
        }
    }

    if (transparent != -1 && colors) {
        gdImageColorTransparent(dst, gdImageColorExact(dst, red, green, blue));
    }

    sharpen = ngx_http_image_filter_get_value(r, conf->shcv, conf->sharpen);
    if (sharpen > 0) {
        gdImageSharpen(dst, sharpen);
    }

    out = ngx_http_image_out(r, ctx->type, dst, &size);

    ngx_log_debug3(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "image: %d x %d %d", sx, sy, colors);

    gdImageDestroy(dst);
    ngx_pfree(r->pool, ctx->image);

    if (out == NULL) {
        return NULL;
    }

    cln = ngx_pool_cleanup_add(r->pool, 0);
    if (cln == NULL) {
        gdFree(out);
        return NULL;
    }

    b = ngx_pcalloc(r->pool, sizeof(ngx_buf_t));
    if (b == NULL) {
        gdFree(out);
        return NULL;
    }

    cln->handler = ngx_http_image_cleanup;
    cln->data = out;

    b->pos = out;
    b->last = out + size;
    b->memory = 1;
    b->last_buf = 1;

    ngx_http_image_length(r, b);

    return b;
}


static gdImagePtr
ngx_http_image_source(ngx_http_request_t *r, ngx_http_image_filter_ctx_t *ctx)
{
    char        *failed;
    gdImagePtr   img;

    img = NULL;

    switch (ctx->type) {

    case NGX_HTTP_IMAGE_JPEG:
        img = gdImageCreateFromJpegPtr(ctx->length, ctx->image);
        failed = "gdImageCreateFromJpegPtr() failed";
        break;

    case NGX_HTTP_IMAGE_GIF:
        img = gdImageCreateFromGifPtr(ctx->length, ctx->image);
        failed = "gdImageCreateFromGifPtr() failed";
        break;

    case NGX_HTTP_IMAGE_PNG:
        img = gdImageCreateFromPngPtr(ctx->length, ctx->image);
        failed = "gdImageCreateFromPngPtr() failed";
        break;

    default:
        failed = "unknown image type";
        break;
    }

    if (img == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, failed);
    }

    return img;
}


static gdImagePtr
ngx_http_image_new(ngx_http_request_t *r, int w, int h, int colors)
{
    gdImagePtr  img;

    if (colors == 0) {
        img = gdImageCreateTrueColor(w, h);

        if (img == NULL) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "gdImageCreateTrueColor() failed");
            return NULL;
        }

    } else {
        img = gdImageCreate(w, h);

        if (img == NULL) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "gdImageCreate() failed");
            return NULL;
        }
    }

    return img;
}


static u_char *
ngx_http_image_out(ngx_http_request_t *r, ngx_uint_t type, gdImagePtr img,
    int *size)
{
    char                          *failed;
    u_char                        *out;
    ngx_int_t                      jq;
    ngx_http_image_filter_conf_t  *conf;

    out = NULL;

    switch (type) {

    case NGX_HTTP_IMAGE_JPEG:
        conf = ngx_http_get_module_loc_conf(r, ngx_http_image_filter_module);

        jq = ngx_http_image_filter_get_value(r, conf->jqcv, conf->jpeg_quality);
        if (jq <= 0) {
            return NULL;
        }

        out = gdImageJpegPtr(img, size, jq);
        failed = "gdImageJpegPtr() failed";
        break;

    case NGX_HTTP_IMAGE_GIF:
        out = gdImageGifPtr(img, size);
        failed = "gdImageGifPtr() failed";
        break;

    case NGX_HTTP_IMAGE_PNG:
        //out = gdImagePngPtr(img, size);
		//png will be bigger than ori,so use jpg to show
		jq = 90;
		out = gdImageJpegPtr(img, size, jq);
        failed = "gdImagePngPtr() failed";
        break;

    default:
        failed = "unknown image type";
        break;
    }

    if (out == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, failed);
    }

    return out;
}


static void
ngx_http_image_cleanup(void *data)
{
    gdFree(data);
}

static void
ngx_http_image_webp_cleanup(void *data)
{
    free(data);
}

static ngx_uint_t
ngx_http_image_filter_get_value(ngx_http_request_t *r,
    ngx_http_complex_value_t *cv, ngx_uint_t v)
{
    ngx_str_t  val;

    if (cv == NULL) {
        return v;
    }

    if (ngx_http_complex_value(r, cv, &val) != NGX_OK) {
        return 0;
    }

    return ngx_http_image_filter_value(&val);
}


static ngx_uint_t
ngx_http_image_filter_value(ngx_str_t *value)
{
    ngx_int_t  n;

    if (value->len == 1 && value->data[0] == '-') {
        return (ngx_uint_t) -1;
    }

    n = ngx_atoi(value->data, value->len);

    if (n > 0) {
        return (ngx_uint_t) n;
    }

    return 0;
}


static void *
ngx_http_image_filter_create_conf(ngx_conf_t *cf)
{
    ngx_http_image_filter_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_image_filter_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    /*
     * set by ngx_pcalloc():
     *
     *     conf->width = 0;
     *     conf->height = 0;
     *     conf->angle = 0;
     *     conf->wcv = NULL;
     *     conf->hcv = NULL;
     *     conf->acv = NULL;
     *     conf->jqcv = NULL;
     *     conf->shcv = NULL;
     */

    conf->filter = NGX_CONF_UNSET_UINT;
    conf->jpeg_quality = NGX_CONF_UNSET_UINT;
    conf->sharpen = NGX_CONF_UNSET_UINT;
    conf->transparency = NGX_CONF_UNSET;
    conf->save_cache = NGX_CONF_UNSET;
    conf->lookup_cache = NGX_CONF_UNSET;
    conf->buffer_size = NGX_CONF_UNSET_SIZE;

    ngx_str_null(&conf->cache_path);

    return conf;
}


static char *
ngx_http_image_filter_merge_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_image_filter_conf_t *prev = parent;
    ngx_http_image_filter_conf_t *conf = child;

    if (conf->filter == NGX_CONF_UNSET_UINT) {

        if (prev->filter == NGX_CONF_UNSET_UINT) {
            conf->filter = NGX_HTTP_IMAGE_OFF;

        } else {
            conf->filter = prev->filter;
            conf->width = prev->width;
            conf->height = prev->height;
            conf->angle = prev->angle;
            conf->wcv = prev->wcv;
            conf->hcv = prev->hcv;
            conf->acv = prev->acv;
        }
    }

    if (conf->jpeg_quality == NGX_CONF_UNSET_UINT) {

        /* 75 is libjpeg default quality */
        ngx_conf_merge_uint_value(conf->jpeg_quality, prev->jpeg_quality, 75);

        if (conf->jqcv == NULL) {
            conf->jqcv = prev->jqcv;
        }
    }

    if (conf->sharpen == NGX_CONF_UNSET_UINT) {
        ngx_conf_merge_uint_value(conf->sharpen, prev->sharpen, 0);

        if (conf->shcv == NULL) {
            conf->shcv = prev->shcv;
        }
    }

    ngx_conf_merge_value(conf->transparency, prev->transparency, 1);
    ngx_conf_merge_value(conf->save_cache, prev->save_cache, 0);
    ngx_conf_merge_value(conf->lookup_cache, prev->lookup_cache, 0);

    ngx_conf_merge_str_value(conf->cache_path, prev->cache_path, "");

    ngx_conf_merge_size_value(conf->buffer_size, prev->buffer_size,
                              1 * 1024 * 1024);

    return NGX_CONF_OK;
}


static char *
ngx_http_image_filter(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_image_filter_conf_t *imcf = conf;

    ngx_str_t                         *value;
    ngx_int_t                          n;
    ngx_uint_t                         i;
    ngx_http_complex_value_t           cv;
    ngx_http_compile_complex_value_t   ccv;

    value = cf->args->elts;

    i = 1;

    if (cf->args->nelts == 2) {
        if (ngx_strcmp(value[i].data, "off") == 0) {
            imcf->filter = NGX_HTTP_IMAGE_OFF;

        } else if (ngx_strcmp(value[i].data, "test") == 0) {
            imcf->filter = NGX_HTTP_IMAGE_TEST;

        } else if (ngx_strcmp(value[i].data, "size") == 0) {
            imcf->filter = NGX_HTTP_IMAGE_SIZE;

        } else {
            goto failed;
        }

        return NGX_CONF_OK;

    } else if (cf->args->nelts == 3) {

        if (ngx_strcmp(value[i].data, "rotate") == 0) {
            if (imcf->filter != NGX_HTTP_IMAGE_RESIZE
                && imcf->filter != NGX_HTTP_IMAGE_CROP)
            {
                imcf->filter = NGX_HTTP_IMAGE_ROTATE;
            }

            ngx_memzero(&ccv, sizeof(ngx_http_compile_complex_value_t));

            ccv.cf = cf;
            ccv.value = &value[++i];
            ccv.complex_value = &cv;

            if (ngx_http_compile_complex_value(&ccv) != NGX_OK) {
                return NGX_CONF_ERROR;
            }

            if (cv.lengths == NULL) {
                n = ngx_http_image_filter_value(&value[i]);

                if (n != 90 && n != 180 && n != 270) {
                    goto failed;
                }

                imcf->angle = (ngx_uint_t) n;

            } else {
                imcf->acv = ngx_palloc(cf->pool,
                                       sizeof(ngx_http_complex_value_t));
                if (imcf->acv == NULL) {
                    return NGX_CONF_ERROR;
                }

                *imcf->acv = cv;
            }

            return NGX_CONF_OK;

        } else {
            goto failed;
        }
    }

    if (ngx_strcmp(value[i].data, "resize") == 0) {
        imcf->filter = NGX_HTTP_IMAGE_RESIZE;

    } else if (ngx_strcmp(value[i].data, "crop") == 0) {
        imcf->filter = NGX_HTTP_IMAGE_CROP;

    } else {
        goto failed;
    }

    ngx_memzero(&ccv, sizeof(ngx_http_compile_complex_value_t));

    ccv.cf = cf;
    ccv.value = &value[++i];
    ccv.complex_value = &cv;

    if (ngx_http_compile_complex_value(&ccv) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    if (cv.lengths == NULL) {
        n = ngx_http_image_filter_value(&value[i]);

        if (n == 0) {
            goto failed;
        }

        imcf->width = (ngx_uint_t) n;

    } else {
        imcf->wcv = ngx_palloc(cf->pool, sizeof(ngx_http_complex_value_t));
        if (imcf->wcv == NULL) {
            return NGX_CONF_ERROR;
        }

        *imcf->wcv = cv;
    }

    ngx_memzero(&ccv, sizeof(ngx_http_compile_complex_value_t));

    ccv.cf = cf;
    ccv.value = &value[++i];
    ccv.complex_value = &cv;

    if (ngx_http_compile_complex_value(&ccv) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    if (cv.lengths == NULL) {
        n = ngx_http_image_filter_value(&value[i]);

        if (n == 0) {
            goto failed;
        }

        imcf->height = (ngx_uint_t) n;

    } else {
        imcf->hcv = ngx_palloc(cf->pool, sizeof(ngx_http_complex_value_t));
        if (imcf->hcv == NULL) {
            return NGX_CONF_ERROR;
        }

        *imcf->hcv = cv;
    }

    return NGX_CONF_OK;

failed:

    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "invalid parameter \"%V\"",
                       &value[i]);

    return NGX_CONF_ERROR;
}


static char *
ngx_http_image_filter_jpeg_quality(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf)
{
    ngx_http_image_filter_conf_t *imcf = conf;

    ngx_str_t                         *value;
    ngx_int_t                          n;
    ngx_http_complex_value_t           cv;
    ngx_http_compile_complex_value_t   ccv;

    value = cf->args->elts;

    ngx_memzero(&ccv, sizeof(ngx_http_compile_complex_value_t));

    ccv.cf = cf;
    ccv.value = &value[1];
    ccv.complex_value = &cv;

    if (ngx_http_compile_complex_value(&ccv) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    if (cv.lengths == NULL) {
        n = ngx_http_image_filter_value(&value[1]);

        if (n <= 0) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "invalid value \"%V\"", &value[1]);
            return NGX_CONF_ERROR;
        }

        imcf->jpeg_quality = (ngx_uint_t) n;

    } else {
        imcf->jqcv = ngx_palloc(cf->pool, sizeof(ngx_http_complex_value_t));
        if (imcf->jqcv == NULL) {
            return NGX_CONF_ERROR;
        }

        *imcf->jqcv = cv;
    }

    return NGX_CONF_OK;
}


static char *
ngx_http_image_filter_sharpen(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf)
{
    ngx_http_image_filter_conf_t *imcf = conf;

    ngx_str_t                         *value;
    ngx_int_t                          n;
    ngx_http_complex_value_t           cv;
    ngx_http_compile_complex_value_t   ccv;

    value = cf->args->elts;

    ngx_memzero(&ccv, sizeof(ngx_http_compile_complex_value_t));

    ccv.cf = cf;
    ccv.value = &value[1];
    ccv.complex_value = &cv;

    if (ngx_http_compile_complex_value(&ccv) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    if (cv.lengths == NULL) {
        n = ngx_http_image_filter_value(&value[1]);

        if (n < 0) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "invalid value \"%V\"", &value[1]);
            return NGX_CONF_ERROR;
        }

        imcf->sharpen = (ngx_uint_t) n;

    } else {
        imcf->shcv = ngx_palloc(cf->pool, sizeof(ngx_http_complex_value_t));
        if (imcf->shcv == NULL) {
            return NGX_CONF_ERROR;
        }

        *imcf->shcv = cv;
    }

    return NGX_CONF_OK;
}


static ngx_int_t
ngx_http_image_filter_init(ngx_conf_t *cf)
{
    //ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "ngx_http_image_filter_init");
    
    //for fastdfs mkdir
	//ngx_image_cache_mkdir("/data/imagecache",cf->log);	
    ngx_http_next_header_filter = ngx_http_top_header_filter;
    ngx_http_top_header_filter = ngx_http_image_header_filter;

    ngx_http_next_body_filter = ngx_http_top_body_filter;
    ngx_http_top_body_filter = ngx_http_image_body_filter;

    return NGX_OK;
}
