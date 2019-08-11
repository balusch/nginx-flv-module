# nginx-flv-module

## About

This nginx module is based on the [nginx_flv_module](https://github.com/nginx/nginx/blob/master/src/http/modules/ngx_http_flv_module.c).

The original module just supports the `start` byte offset argument, but this module also supports time offset(use `start`, `end` arguments in uri).

## Build

Build [nginx](http://nginx.org) with the module:

``` sh
./configure --add-module=/path/to/nginx-flv-module
```

**DO NOT** configure with `with-http_flv_module`.

## Directives

### flv

| Syntax | Context |
|--------|---------|
|`flv`   |location|

Enable support for flv file.

### flv_time_offset

| Syntax | Context |
|--------|---------|
|`flv_time_offset on/off`|http, server, location|

Enable or disable support for time offset.

### flv_with_metadata

| Syntax | Context |
|--------|---------|
|`flv_with_metadata on/off`|http, server, location|

Enable or disable sending metadata(if existed).

### flv_buffer_size

| Syntax | Context |
|--------|---------|
|`flv_buffer_size size` |http, server, location|

Set the initial size of the buffer used for processing FLV files.

### flv_max_buffer_size

| Syntax | Context |
|--------|---------|
|`flv_max_buffer_size size`|http, server, location|

Set the maximum size of the buffer used for processing FLV files.

## Example

``` nginx
http {
    server {
        listen          80;
        server_name     localhost;

        root            /media/FLV;
        location ~\.flv {
            flv;
            flv_time_offset         off;
            flv_with_metadata       off;
            flv_buffer_size         512k;
            flv_max_buffer_size     2M;
        }
    }
}
```

* with `time_offset` argument:

![flv-with-time_offset](https://raw.githubusercontent.com/BalusChen/Markdown_Photos/master/L78Z/flv-with-time_offset.png)

* without `time_offset` argument:

![flv-without-time_offset](https://raw.githubusercontent.com/BalusChen/Markdown_Photos/master/L78Z/flv-without-time_offset.png)
