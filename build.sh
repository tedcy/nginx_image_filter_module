function check_exist_f()
{
	if [ ! -f $1 ];then
		echo "$1 doesn't exist"
		exit 1
	fi
}

echo "init installation of nginx ..."
readonly nginx_tar="nginx-1.2.9.tar.gz"
readonly nginx_src_path="nginx-1.2.9"
readonly lib_webp_tar="libwebp-0.4.3.tar.gz"
readonly lib_webp_src_path="libwebp-0.4.3"

check_exist_f $nginx_tar
check_exist_f $lib_webp_tar

tar xf $nginx_tar
tar xf $lib_webp_tar

userdel nginx
groupdel nginx
usermod –G nginx nginx

rm -rf /home/nginx

useradd nginx -s /sbin/nologin -d /home/nginx

yum -y install gd gd-devel pcre-devel

cd $lib_webp_src_path
./configure
make
make install
ldconfig
cd ..
rm -rf $lib_webp_src_path

cd $nginx_src_path
cp ../ngx_http_image_filter_module.c src/http/modules/ngx_http_image_filter_module.c
./configure \
    --with-ld-opt='-lwebp' \
    --prefix=/data/nginx \
    --error-log-path=/data/log/nginx/error.log \
    --http-log-path=/data/log/nginx/access.log \
    --pid-path=/var/run/nginx/nginx.pid  \
    --lock-path=/var/lock/nginx.lock \
    --user=nginx \
    --group=nginx \
    --with-http_ssl_module \
    --with-http_flv_module \
    --with-http_stub_status_module \
    --with-http_gzip_static_module \
    --http-client-body-temp-path=/var/tmp/nginx/client/ \
    --http-proxy-temp-path=/var/tmp/nginx/proxy/ \
    --http-fastcgi-temp-path=/var/tmp/nginx/fcgi/ \
    --http-uwsgi-temp-path=/var/tmp/nginx/uwsgi \
    --http-scgi-temp-path=/var/tmp/nginx/scgi \
    --with-pcre \
    --with-file-aio \
    --with-http_image_filter_module
make
make install
cd ..
cp conf/nginx.conf /data/nginx/conf/nginx.conf
cp conf/default.conf /data/nginx/conf/vhosts
rm -rf $nginx_src_path
