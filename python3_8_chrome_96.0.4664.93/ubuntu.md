1. 测试脚本
    ```
    import ssl
    import httpx
    ssl_context = ssl.SSLContext(protocol=ssl.PROTOCOL_TLS)
    #ssl_context.set_alpn_protocols(["h2", "http/1.1"])
    CIPHERS = ":".join(
        [
            "TLS_AES_128_GCM_SHA256",
            "TLS_AES_256_GCM_SHA384",
            "TLS_CHACHA20_POLY1305_SHA256",
            "ECDHE-ECDSA-AES128-GCM-SHA256",
            "ECDHE-RSA-AES128-GCM-SHA256",
            "ECDHE-ECDSA-AES256-GCM-SHA384",
            "ECDHE-RSA-AES256-GCM-SHA384",
            "ECDHE-ECDSA-CHACHA20-POLY1305",
            "ECDHE-RSA-CHACHA20-POLY1305",
            "ECDHE-RSA-AES128-SHA",
            "ECDHE-RSA-AES256-SHA",
            "AES128-GCM-SHA256",
            "AES256-GCM-SHA384",
            "AES128-SHA",
            "AES256-SHA"
        ]
    )
    ssl_context.set_ciphers(CIPHERS)
    ssl_context.set_grease_enabled(True)
    ssl_context.enable_signed_cert_timestamps()
    ssl_context.enable_ocsp_stapling()
    ssl_context.add_cert_compression_brotli()
    client = httpx.Client(http2=True, verify=ssl_context)

    headers = {
        "user-agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.110 Safari/537.36"
    }

    response = client.get("https://www.baidu.com", headers=headers)

    print(response.http_version)
    ```
2. 先用未经修改的boringssl去编译python
    1. 编译boringssl
        ```
        mkdir build && cd build && cmake ../ && make && cd ../
        mkdir -p .openssl/lib && cd .openssl && ln -s ../include . && cd ../
        cp build/crypto/libcrypto.a build/ssl/libssl.a .openssl/lib
        cp -R .openssl/lib ./
        ```
    2. 编译python
        ```
        ./configure --with-openssl=/home/db/python_tls/boringssl --prefix=/home/db/python_tls/python
        ```
    2. `vim Modules/Setup`，找到SSL，修改为下面的内容
        ```
        SSL=/home/db/python_tls/boringssl
        _ssl _ssl.c \
            -DUSE_SSL -I$(SSL)/include -I$(SSL)/include/openssl \
            -L$(SSL)/lib -lssl -lcrypto
        ```
    3. `make CFLAGS="-Wno-error" && make install`
    4. 报错
        ```
        ./Modules/_ssl/debughelpers.c:202:51: error: ‘BIO_FP_TEXT’ undeclared (first use in this function)
            202 |     self->keylog_bio = BIO_new_fp(fp, BIO_CLOSE | BIO_FP_TEXT);
                |                                                   ^~~~~~~~~~~
        
        ./Modules/_ssl.c:993:25: error: ‘SSL_VERIFY_POST_HANDSHAKE’ undeclared (first use in this function)
        993 |                 mode |= SSL_VERIFY_POST_HANDSHAKE;
            |                         ^~~~~~~~~~~~~~~~~~~~~~~~~
        ./Modules/_ssl.c:998:13: error: implicit declaration of function ‘SSL_set_post_handshake_auth’; did you mean ‘SSL_set_handshake_hints’? [-Werror=implicit-function-declaration]
        998 |             SSL_set_post_handshake_auth(self->ssl, 1);
            |             ^~~~~~~~~~~~~~~~~~~~~~~~~~~
            |             SSL_set_handshake_hints
        
        ./Modules/_ssl.c: In function ‘_ssl__SSLSocket_verify_client_post_handshake_impl’:
        ./Modules/_ssl.c:2825:15: error: implicit declaration of function ‘SSL_verify_client_post_handshake’; did you mean ‘_ssl__SSLSocket_verify_client_post_handshake’? [-Werror=implicit-function-declaration]
        2825 |     int err = SSL_verify_client_post_handshake(self->ssl);
            |               ^~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
            |               _ssl__SSLSocket_verify_client_post_handshake
        ./Modules/_ssl.c: In function ‘_ssl__SSLContext_impl’:
        ./Modules/_ssl.c:3288:5: error: implicit declaration of function ‘SSL_CTX_set_post_handshake_auth’ [-Werror=implicit-function-declaration]
        3288 |     SSL_CTX_set_post_handshake_auth(self->ctx, self->post_handshake_auth);
            |     ^~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
        ./Modules/_ssl.c: In function ‘_ssl__SSLContext_get_ciphers_impl’:
        ./Modules/_ssl.c:3389:19: warning: comparison of integer expressions of different signedness: ‘int’ and ‘size_t’ {aka ‘long unsigned int’} [-Wsign-compare]
        3389 |     for (i = 0; i < sk_SSL_CIPHER_num(sk); i++) {
            |                   ^
        ./Modules/_ssl.c: In function ‘get_num_tickets’:
        ./Modules/_ssl.c:3729:30: error: implicit declaration of function ‘SSL_CTX_get_num_tickets’; did you mean ‘get_num_tickets’? [-Werror=implicit-function-declaration]
        3729 |     return PyLong_FromSize_t(SSL_CTX_get_num_tickets(self->ctx));
            |                              ^~~~~~~~~~~~~~~~~~~~~~~
            |                              get_num_tickets
        ./Modules/_ssl.c: In function ‘set_num_tickets’:
        ./Modules/_ssl.c:3747:9: error: implicit declaration of function ‘SSL_CTX_set_num_tickets’; did you mean ‘set_num_tickets’? [-Werror=implicit-function-declaration]
        3747 |     if (SSL_CTX_set_num_tickets(self->ctx, num) != 1) {
            |         ^~~~~~~~~~~~~~~~~~~~~~~
            |         set_num_tickets
        ```
    5. `BIO_FP_TEXT` 在 `include/openssl/bio.h`里面找地方添加 `#define BIO_FP_TEXT 0x10`
    6. `SSL_VERIFY_POST_HANDSHAKE` 在 `include/openssl/ssl.h` 里面的 `#define SSL_VERIFY_NONE 0x00`后面添加 `#define SSL_VERIFY_POST_HANDSHAKE 0x08`
    7. `vim Modules/_ssl.c` 注释掉下面的，这是tls1.3的，目前用不到，暂时先注释掉，用到tls1.3的时候，可以看看用boringssl的SSL_process_quic_post_handshake来代替可不可以
        ```
        SSL_set_post_handshake_auth(self->ssl, 1);
        ```
    8. `vim Modules/_ssl.c` 注释掉下面的，这是tls1.3的，目前用不到，暂时先注释掉，用到tls1.3的时候，再看怎么弄
        ```
        int err = SSL_verify_client_post_handshake(self->ssl);
        if (err == 0)
            return _setSSLError(NULL, 0, __FILE__, __LINE__);
        else

        SSL_CTX_set_post_handshake_auth(self->ctx, self->post_handshake_auth);
        ```
    9. `vim Modules/_ssl.c` 注释掉set_num_tickets有关的还有get_num_tickets有关的
        ```
        #if (OPENSSL_VERSION_NUMBER >= 0x10101000L) && !defined(LIBRESSL_VERSION_NUMBER)
        static PyObject *
        get_num_tickets(PySSLContext *self, void *c)
        {
            return PyLong_FromSize_t(SSL_CTX_get_num_tickets(self->ctx));
        }

        static int
        set_num_tickets(PySSLContext *self, PyObject *arg, void *c)
        {
            long num;
            if (!PyArg_Parse(arg, "l", &num))
                return -1;
            if (num < 0) {
                PyErr_SetString(PyExc_ValueError, "value must be non-negative");
                return -1;
            }
            if (self->protocol != PY_SSL_VERSION_TLS_SERVER) {
                PyErr_SetString(PyExc_ValueError,
                                "SSLContext is not a server context.");
                return -1;
            }
            if (SSL_CTX_set_num_tickets(self->ctx, num) != 1) {
                PyErr_SetString(PyExc_ValueError, "failed to set num tickets.");
                return -1;
            }
            return 0;
        }

        PyDoc_STRVAR(PySSLContext_num_tickets_doc,
        "Control the number of TLSv1.3 session tickets");
        #endif /* OpenSSL 1.1.1 */
        ```
        ```
            {"num_tickets", (getter) get_num_tickets,
                    (setter) set_num_tickets, PySSLContext_num_tickets_doc},
        ```
3. 添加grease 修改python 
    1. `vim Modules/_ssl.c` `_ssl__SSLContext_set_ciphers_impl`前面加上
        ```
        static PyObject *
        _ssl__SSLContext_set_grease_enabled_impl(PySSLContext *self, int enabled)
        {
            SSL_CTX_set_grease_enabled(self->ctx, enabled);
            Py_RETURN_NONE;
        }
        ```
    2. `vim Modules/clinic/_ssl.c.h`在`PyDoc_STRVAR(_ssl__SSLContext_set_ciphers__doc__`前面加上
        ```
        PyDoc_STRVAR(_ssl__SSLContext_set_grease_enabled__doc__,
        "set_grease_enabled($self, enabled, /)\n"
        "--\n"
        "\n");
        #define _SSL__SSLCONTEXT_SET_GREASE_ENABLED_METHODDEF    \
            {"set_grease_enabled", (PyCFunction)_ssl__SSLContext_set_grease_enabled, METH_O, _ssl__SSLContext_set_grease_enabled__doc__},

        static PyObject *
        _ssl__SSLContext_set_grease_enabled_impl(PySSLContext *self, int enabled);

        static PyObject *
        _ssl__SSLContext_set_grease_enabled(PySSLContext *self, int enabled)
        {
            return _ssl__SSLContext_set_grease_enabled_impl(self, enabled);
        }
        ```
    3.  `vim Modules/_ssl.c` 在 `static struct PyMethodDef context_methods[]` 添加 
        ```
        _SSL__SSLCONTEXT_SET_GREASE_ENABLED_METHODDEF
        ```
4. application_layer_protocol_negotiation `vim env/lib/python3.8/site-packages/httpcore/_sync/connection.py` h2和http/1.1的顺序调换位置
5. `status_request`添加 修改Python源码
    1. `vim Modules/_ssl.c` 在 `_ssl__SSLContext_set_grease_enabled_impl`后面添加`_ssl__SSLContext_enable_ocsp_stapling_impl`
        ```
        static PyObject *
        _ssl__SSLContext_enable_ocsp_stapling_impl(PySSLContext *self)
        {
            SSL_CTX_enable_ocsp_stapling(self->ctx);
            Py_RETURN_NONE;
        }
        ```
    2. `vim Modules/clinic/_ssl.c.h` 在`_ssl__SSLContext_set_grease_enabled__doc__`的内容后面添加
        ```
        PyDoc_STRVAR(_ssl__SSLContext_enable_ocsp_stapling__doc__,
        "enable_ocsp_stapling($self, /)\n"
        "--\n"
        "\n");

        #define _SSL__SSLCONTEXT_ENABLE_OCSP_STAPLING_METHODDEF    \
            {"enable_ocsp_stapling", (PyCFunction)_ssl__SSLContext_enable_ocsp_stapling, METH_NOARGS, _ssl__SSLContext_enable_ocsp_stapling__doc__},

        static PyObject *
        _ssl__SSLContext_enable_ocsp_stapling_impl(PySSLContext *self);

        static PyObject *
        _ssl__SSLContext_enable_ocsp_stapling(PySSLContext *self, PyObject *Py_UNUSED(ignored))
        {
            return _ssl__SSLContext_enable_ocsp_stapling_impl(self);
        }
        ```
    3. `vim Modules/_ssl.c` 在 `static struct PyMethodDef context_methods[]` 添加 
        ```
        _SSL__SSLCONTEXT_ENABLE_OCSP_STAPLING_METHODDEF
        ```
6. 在 `ssl/extensions.cc`的kVerifySignatureAlgorithms里面最后去掉`SSL_SIGN_RSA_PKCS1_SHA1`
7. signed_certificate_timestamp 添加
    1. `vim Modules/_ssl.c` 在 `_ssl__SSLContext_enable_ocsp_stapling_impl`后面添加`_ssl__SSLContext_enable_signed_cert_timestamps_impl`
        ```
        static PyObject *
        _ssl__SSLContext_enable_signed_cert_timestamps_impl(PySSLContext *self)
        {
            SSL_CTX_enable_signed_cert_timestamps(self->ctx);
            Py_RETURN_NONE;
        }
        ```
    2. `vim Modules/clinic/_ssl.c.h` 在`_ssl__SSLContext_enable_ocsp_stapling__doc__`的内容后面添加
        ```
        PyDoc_STRVAR(_ssl__SSLContext_enable_signed_cert_timestamps__doc__,
        "enable_signed_cert_timestamps($self, /)\n"
        "--\n"
        "\n");

        #define _SSL__SSLCONTEXT_ENABLE_SIGNED_CERT_TIMESTAMPS_METHODDEF    \
            {"enable_signed_cert_timestamps", (PyCFunction)_ssl__SSLContext_enable_signed_cert_timestamps, METH_NOARGS, _ssl__SSLContext_enable_signed_cert_timestamps__doc__},

        static PyObject *
        _ssl__SSLContext_enable_signed_cert_timestamps_impl(PySSLContext *self);

        static PyObject *
        _ssl__SSLContext_enable_signed_cert_timestamps(PySSLContext *self, PyObject *Py_UNUSED(ignored))
        {
            return _ssl__SSLContext_enable_signed_cert_timestamps_impl(self);
        }
        ```
    3. `vim Modules/_ssl.c` 在 `static struct PyMethodDef context_methods[]` 添加 
        ```
        _SSL__SSLCONTEXT_ENABLE_SIGNED_CERT_TIMESTAMPS_METHODDEF
        ```
8. compress_certificate
    1. `git clone https://github.com/bagder/libbrotli`
    2. `cd libbrotli`
    3. `./autogen.sh && ./configure --prefix=/home/db/python_tls/libbrotli/build/ && make && make install`
    5. brotli的动态库在`build/lib/`下面的两个`.a`文件
    6. 静态库在`build/include/brotli/`
    7. `vim include/openssl/ssl.h` 在 `SSL_CTX_add_cert_compression_alg`后面添加 `OPENSSL_EXPORT int SSL_CTX_add_cert_compression_brotli(SSL_CTX *ctx);`
    8. `vim ssl/ssl_lib.cc` 在SSL_CTX_add_cert_compression_alg后面添加
        ```
        #include "../third_party/brotli/include/brotli/decode.h"
        int DecompressBrotliCert(SSL* ssl, CRYPTO_BUFFER** out, size_t uncompressed_len, const uint8_t* in, size_t in_len);
        int DecompressBrotliCert(SSL* ssl, CRYPTO_BUFFER** out, size_t uncompressed_len, const uint8_t* in, size_t in_len) {
            uint8_t* data;
            bssl::UniquePtr<CRYPTO_BUFFER> decompressed(
                CRYPTO_BUFFER_alloc(&data, uncompressed_len));
            if (!decompressed) {
                return 0;
            }
            size_t output_size = uncompressed_len;
            if (BrotliDecoderDecompress(in_len, in, &output_size, data) !=
                    BROTLI_DECODER_RESULT_SUCCESS ||
                output_size != uncompressed_len) {
                return 0;
            }
            *out = decompressed.release();
            return 1;
        }

        int SSL_CTX_add_cert_compression_brotli(SSL_CTX *ctx) {
            return SSL_CTX_add_cert_compression_alg(ctx, 2, nullptr, DecompressBrotliCert);
        }
        ```
    9. 新建文件夹 `third_party/brotli/include/brotli/` 将brotli的头文件拷贝过来
    10. `vim ssl/CMakeLists.txt`
        在46行添加  `target_link_libraries(ssl libbrotlidec.a)`
        将61行的`target_link_libraries(ssl_test test_support_lib boringssl_gtest ssl crypto)` 修改为`target_link_libraries(ssl_test test_support_lib boringssl_gtest ssl crypto libbrotlidec.a)`
    11. `mkdir build && cd build && cmake ../ && make && cd ../`
    12. `mkdir -p .openssl/lib && cd .openssl && ln -s ../include . && cd ../`
    13. `cp build/crypto/libcrypto.a build/ssl/libssl.a .openssl/lib`
    14. `cp -R .openssl/lib ./`
    15. `cd lib && mkdir tmp && cp libssl.a libssl.a.bak && cp libssl.a tmp/ && cd tmp && ar x libssl.a && ar x /usr/local/lib/libbrotlidec.a && ar rc libssl.a *.o && cp libssl.a ../`
    16. `vim Modules/_ssl.c` 在`_ssl__SSLContext_enable_signed_cert_timestamps_impl` 后面添加
        ```
        static PyObject *
        _ssl__SSLContext_add_cert_compression_brotli_impl(PySSLContext *self)
        {
            SSL_CTX_add_cert_compression_brotli(self->ctx);
            Py_RETURN_NONE;
        }
        ```
    17. `vim Modules/clinic/_ssl.c.h` 在`_ssl__SSLContext_enable_signed_cert_timestamps`后面添加
        ```
        PyDoc_STRVAR(_ssl__SSLContext_add_cert_compression_brotli__doc__,
        "add_cert_compression_brotli($self, /)\n"
        "--\n"
        "\n");

        #define _SSL__SSLCONTEXT_ADD_CERT_COMPRESSION_BROTLI_METHODDEF    \
            {"add_cert_compression_brotli", (PyCFunction)_ssl__SSLContext_add_cert_compression_brotli, METH_NOARGS, _ssl__SSLContext_add_cert_compression_brotli__doc__},

        static PyObject *
        _ssl__SSLContext_add_cert_compression_brotli_impl(PySSLContext *self);

        static PyObject *
        _ssl__SSLContext_add_cert_compression_brotli(PySSLContext *self, PyObject *Py_UNUSED(ignored))
        {
            return _ssl__SSLContext_add_cert_compression_brotli_impl(self);
        }
        ```
    18. `vim Modules/_ssl.c` 在 `static struct PyMethodDef context_methods[]` 添加 
        ```
        _SSL__SSLCONTEXT_ADD_CERT_COMPRESSION_BROTLI_METHODDEF
        ```
9. application_settings
    1. boringssl `vim include/openssl/ssl.h` 在 
        ```
        OPENSSL_EXPORT int SSL_add_application_settings(SSL *ssl, const uint8_t *proto,
                                                size_t proto_len,
                                                const uint8_t *settings,
                                                size_t settings_len);
        ```
        后面添加 
        ```
        OPENSSL_EXPORT int SSL_add_h2_application_settings(SSL *ssl);
        ```
    2. `vim ssl/ssl_lib.cc` 在 `SSL_add_application_settings` 后面添加
        ```
        int SSL_add_h2_application_settings(SSL *ssl) {
            static const uint8_t kList[] = {'h', '2'};
            static const uint8_t ksetList[] = {};
            return SSL_add_application_settings(ssl, kList, sizeof(kList), ksetList, sizeof(ksetList));
        }
        ```
    3. python `vim Modules/_ssl.c` 在 `_ssl__SSLSocket_do_handshake_impl` 函数前面添加
        ```
        static PyObject *
        _ssl__SSLSocket_add_h2_application_settings_impl(PySSLSocket *self)
        {
            int ret = SSL_add_h2_application_settings(self->ssl);
            if (ret != 1) {
                ERR_clear_error();
                PyErr_SetString(PySSLErrorObject,
                                "add_h2_application_settings failed.");
                return NULL;
            }
            Py_RETURN_NONE;
        }
        ```
        在 `PySSLMethods` 里面添加
        ```
        _SSL__SSLSOCKET_ADD_H2_APPLICATION_SETTINGS_METHODDEF
        ```
    4. `vim Modules/clinic/_ssl.c.h` 随便找个地方添加
        ```
        PyDoc_STRVAR(_ssl__SSLSocket_add_h2_application_settings__doc__,
        "add_h2_application_settings($self, /)\n"
        "--\n"
        "\n");

        #define _SSL__SSLSOCKET_ADD_H2_APPLICATION_SETTINGS_METHODDEF    \
            {"add_h2_application_settings", (PyCFunction)_ssl__SSLSocket_add_h2_application_settings, METH_NOARGS, _ssl__SSLSocket_add_h2_application_settings__doc__},

        static PyObject *
        _ssl__SSLSocket_add_h2_application_settings_impl(PySSLSocket *self);

        static PyObject *
        _ssl__SSLSocket_add_h2_application_settings(PySSLSocket *self, PyObject *Py_UNUSED(ignored))
        {
            return _ssl__SSLSocket_add_h2_application_settings_impl(self);
        }
        ```
    5. python源码目录下 Lib/ssl.py 在
        ```
        self._sslobj = self._context._wrap_socket(
                self, server_side, self.server_hostname,
                owner=self, session=self._session,
            )
        ```后面添加`self._sslobj.add_h2_application_settings()`
10. 添加pre_shared_key，  ssl/extension.cc 中的should_offer_psk 决定是否有pre_shared_key 但是强制写true的话，会有错误，用gdb进行调试的话，发现hs的ssl中没有session。在观察chrome和Firefox之后发现，这个属于psk复用，在firefox中psk一开始没有的，经过一次padding结尾后，以后的链接才有了psk，在chrome中观察psk，每次的psk都有一大部分是相同的数据。用自己编译的boringssl_python去请求的serverhello中也返回了psk。但是要在下一次链接使用psk，应该缺乏一些设置存储之类的步骤，目前没办法使用


# 总结
1. sudo apt install vim autoconf libtool golang cmake build-essential libssl-dev zlib1g-dev libbz2-dev libreadline-dev libsqlite3-dev wget curl llvm libncurses5-dev libncursesw5-dev xz-utils tk-dev libffi-dev liblzma-dev
2. 设置go国内源
```
go env -w GO111MODULE=on
go env -w GOPROXY=https://mirrors.aliyun.com/goproxy/,direct
```
3. brotli
    1. `git clone https://github.com/google/brotli`
    2. `cd brotli`
    3. `mkdir out && cd out`
    4. `../configure-cmake && make && make test`
    5. `sudo make install`
4. boringssl
    1. `BIO_FP_TEXT` 在 `include/openssl/bio.h`里面找地方添加 `#define BIO_FP_TEXT 0x10`
    2. `SSL_VERIFY_POST_HANDSHAKE` 在 `include/openssl/ssl.h` 里面的 `#define SSL_VERIFY_NONE 0x00`后面添加 `#define SSL_VERIFY_POST_HANDSHAKE 0x08`
    3. 在 `ssl/extensions.cc`的kVerifySignatureAlgorithms里面最后去掉`SSL_SIGN_RSA_PKCS1_SHA1`
    4. `vim include/openssl/ssl.h` 在 `SSL_CTX_add_cert_compression_alg`后面添加 `OPENSSL_EXPORT int SSL_CTX_add_cert_compression_brotli(SSL_CTX *ctx);`
    5. `vim ssl/ssl_lib.cc` 在SSL_CTX_add_cert_compression_alg后面添加
        ```
        #include "brotli/decode.h"
        int DecompressBrotliCert(SSL* ssl, CRYPTO_BUFFER** out, size_t uncompressed_len, const uint8_t* in, size_t in_len);
        int DecompressBrotliCert(SSL* ssl, CRYPTO_BUFFER** out, size_t uncompressed_len, const uint8_t* in, size_t in_len) {
            uint8_t* data;
            bssl::UniquePtr<CRYPTO_BUFFER> decompressed(
                CRYPTO_BUFFER_alloc(&data, uncompressed_len));
            if (!decompressed) {
                return 0;
            }
            size_t output_size = uncompressed_len;
            if (BrotliDecoderDecompress(in_len, in, &output_size, data) !=
                    BROTLI_DECODER_RESULT_SUCCESS ||
                output_size != uncompressed_len) {
                return 0;
            }
            *out = decompressed.release();
            return 1;
        }

        int SSL_CTX_add_cert_compression_brotli(SSL_CTX *ctx) {
            return SSL_CTX_add_cert_compression_alg(ctx, 2, nullptr, DecompressBrotliCert);
        }
        ```
    6. 新建文件夹 `third_party/brotli/include/brotli/` 将brotli的头文件拷贝过来
    7. `vim ssl/CMakeLists.txt`
        在46行添加  `target_link_libraries(ssl libbrotlidec-static.a libbrotlicomman-static.a)`
        将61行的`target_link_libraries(ssl_test test_support_lib boringssl_gtest ssl crypto)` 修改为`target_link_libraries(ssl_test test_support_lib boringssl_gtest ssl crypto libbrotlidec-static.a libbrotlicomman-static.a)`
    8. boringssl `vim include/openssl/ssl.h` 在 
        ```
        OPENSSL_EXPORT int SSL_add_application_settings(SSL *ssl, const uint8_t *proto,
                                                size_t proto_len,
                                                const uint8_t *settings,
                                                size_t settings_len);
        ```
        后面添加 
        ```
        OPENSSL_EXPORT int SSL_add_h2_application_settings(SSL *ssl);
        ```
    9. `vim ssl/ssl_lib.cc` 在 `SSL_add_application_settings` 后面添加
        ```
        int SSL_add_h2_application_settings(SSL *ssl) {
            static const uint8_t kList[] = {'h', '2'};
            static const uint8_t ksetList[] = {};
            return SSL_add_application_settings(ssl, kList, sizeof(kList), ksetList, sizeof(ksetList));
        }
        ```
    11. `mkdir build && cd build && cmake ../ && make && cd ../`
    12. `mkdir -p .openssl/lib && cd .openssl && ln -s ../include . && cd ../`
    13. `cp build/crypto/libcrypto.a build/ssl/libssl.a .openssl/lib`
    14. `cp -R .openssl/lib ./`
    15. `cd lib && mkdir tmp && cp libssl.a libssl.a.bak && cp libssl.a tmp/ && cd tmp && ar x libssl.a && ar x /usr/local/lib/libbrotlidec-static.a && ar x /usr/local/lib/libbrotlicomman-static.a && ar rc libssl.a *.o && cp libssl.a ../`
5. python
    1. `vim Modules/_ssl.c` 注释掉下面的，这是tls1.3的，目前用不到，暂时先注释掉，用到tls1.3的时候，可以看看用boringssl的SSL_process_quic_post_handshake来代替可不可以
        ```
        SSL_set_post_handshake_auth(self->ssl, 1);
        ```
    2. `vim Modules/_ssl.c` 注释掉下面的，这是tls1.3的，目前用不到，暂时先注释掉，用到tls1.3的时候，再看怎么弄
        ```
        int err = SSL_verify_client_post_handshake(self->ssl);
        if (err == 0)
            return _setSSLError(NULL, 0, __FILE__, __LINE__);
        else

        SSL_CTX_set_post_handshake_auth(self->ctx, self->post_handshake_auth);
        ```
    3. `vim Modules/_ssl.c` 注释掉set_num_tickets有关的还有get_num_tickets有关的
        ```
        #if (OPENSSL_VERSION_NUMBER >= 0x10101000L) && !defined(LIBRESSL_VERSION_NUMBER)
        static PyObject *
        get_num_tickets(PySSLContext *self, void *c)
        {
            return PyLong_FromSize_t(SSL_CTX_get_num_tickets(self->ctx));
        }

        static int
        set_num_tickets(PySSLContext *self, PyObject *arg, void *c)
        {
            long num;
            if (!PyArg_Parse(arg, "l", &num))
                return -1;
            if (num < 0) {
                PyErr_SetString(PyExc_ValueError, "value must be non-negative");
                return -1;
            }
            if (self->protocol != PY_SSL_VERSION_TLS_SERVER) {
                PyErr_SetString(PyExc_ValueError,
                                "SSLContext is not a server context.");
                return -1;
            }
            if (SSL_CTX_set_num_tickets(self->ctx, num) != 1) {
                PyErr_SetString(PyExc_ValueError, "failed to set num tickets.");
                return -1;
            }
            return 0;
        }

        PyDoc_STRVAR(PySSLContext_num_tickets_doc,
        "Control the number of TLSv1.3 session tickets");
        #endif /* OpenSSL 1.1.1 */
        ```
        ```
            {"num_tickets", (getter) get_num_tickets,
                    (setter) set_num_tickets, PySSLContext_num_tickets_doc},
        ```
    4. `vim Modules/_ssl.c` `_ssl__SSLContext_set_ciphers_impl`前面加上
        ```
        static PyObject *
        _ssl__SSLContext_set_grease_enabled_impl(PySSLContext *self, int enabled)
        {
            SSL_CTX_set_grease_enabled(self->ctx, enabled);
            Py_RETURN_NONE;
        }
        ```
    5. `vim Modules/clinic/_ssl.c.h`在`PyDoc_STRVAR(_ssl__SSLContext_set_ciphers__doc__`前面加上
        ```
        PyDoc_STRVAR(_ssl__SSLContext_set_grease_enabled__doc__,
        "set_grease_enabled($self, enabled, /)\n"
        "--\n"
        "\n");
        #define _SSL__SSLCONTEXT_SET_GREASE_ENABLED_METHODDEF    \
            {"set_grease_enabled", (PyCFunction)_ssl__SSLContext_set_grease_enabled, METH_O, _ssl__SSLContext_set_grease_enabled__doc__},

        static PyObject *
        _ssl__SSLContext_set_grease_enabled_impl(PySSLContext *self, int enabled);

        static PyObject *
        _ssl__SSLContext_set_grease_enabled(PySSLContext *self, int enabled)
        {
            return _ssl__SSLContext_set_grease_enabled_impl(self, enabled);
        }
        ```
    6.  `vim Modules/_ssl.c` 在 `static struct PyMethodDef context_methods[]` 添加 
        ```
        _SSL__SSLCONTEXT_SET_GREASE_ENABLED_METHODDEF
        ```
    7. `status_request`添加 修改Python源码
        1. `vim Modules/_ssl.c` 在 `_ssl__SSLContext_set_grease_enabled_impl`后面添加`_ssl__SSLContext_enable_ocsp_stapling_impl`
            ```
            static PyObject *
            _ssl__SSLContext_enable_ocsp_stapling_impl(PySSLContext *self)
            {
                SSL_CTX_enable_ocsp_stapling(self->ctx);
                Py_RETURN_NONE;
            }
            ```
        2. `vim Modules/clinic/_ssl.c.h` 在`_ssl__SSLContext_set_grease_enabled__doc__`的内容后面添加
            ```
            PyDoc_STRVAR(_ssl__SSLContext_enable_ocsp_stapling__doc__,
            "enable_ocsp_stapling($self, /)\n"
            "--\n"
            "\n");

            #define _SSL__SSLCONTEXT_ENABLE_OCSP_STAPLING_METHODDEF    \
                {"enable_ocsp_stapling", (PyCFunction)_ssl__SSLContext_enable_ocsp_stapling, METH_NOARGS, _ssl__SSLContext_enable_ocsp_stapling__doc__},

            static PyObject *
            _ssl__SSLContext_enable_ocsp_stapling_impl(PySSLContext *self);

            static PyObject *
            _ssl__SSLContext_enable_ocsp_stapling(PySSLContext *self, PyObject *Py_UNUSED(ignored))
            {
                return _ssl__SSLContext_enable_ocsp_stapling_impl(self);
            }
            ```
        3. `vim Modules/_ssl.c` 在 `static struct PyMethodDef context_methods[]` 添加 
            ```
            _SSL__SSLCONTEXT_ENABLE_OCSP_STAPLING_METHODDEF
            ```
    8. signed_certificate_timestamp 添加
        1. `vim Modules/_ssl.c` 在 `_ssl__SSLContext_enable_ocsp_stapling_impl`后面添加`_ssl__SSLContext_enable_signed_cert_timestamps_impl`
            ```
            static PyObject *
            _ssl__SSLContext_enable_signed_cert_timestamps_impl(PySSLContext *self)
            {
                SSL_CTX_enable_signed_cert_timestamps(self->ctx);
                Py_RETURN_NONE;
            }
            ```
        2. `vim Modules/clinic/_ssl.c.h` 在`_ssl__SSLContext_enable_ocsp_stapling__doc__`的内容后面添加
            ```
            PyDoc_STRVAR(_ssl__SSLContext_enable_signed_cert_timestamps__doc__,
            "enable_signed_cert_timestamps($self, /)\n"
            "--\n"
            "\n");

            #define _SSL__SSLCONTEXT_ENABLE_SIGNED_CERT_TIMESTAMPS_METHODDEF    \
                {"enable_signed_cert_timestamps", (PyCFunction)_ssl__SSLContext_enable_signed_cert_timestamps, METH_NOARGS, _ssl__SSLContext_enable_signed_cert_timestamps__doc__},

            static PyObject *
            _ssl__SSLContext_enable_signed_cert_timestamps_impl(PySSLContext *self);

            static PyObject *
            _ssl__SSLContext_enable_signed_cert_timestamps(PySSLContext *self, PyObject *Py_UNUSED(ignored))
            {
                return _ssl__SSLContext_enable_signed_cert_timestamps_impl(self);
            }
            ```
        3. `vim Modules/_ssl.c` 在 `static struct PyMethodDef context_methods[]` 添加 
            ```
            _SSL__SSLCONTEXT_ENABLE_SIGNED_CERT_TIMESTAMPS_METHODDEF
            ```
    9. `vim Modules/_ssl.c` 在`_ssl__SSLContext_enable_signed_cert_timestamps_impl` 后面添加
        ```
        static PyObject *
        _ssl__SSLContext_add_cert_compression_brotli_impl(PySSLContext *self)
        {
            SSL_CTX_add_cert_compression_brotli(self->ctx);
            Py_RETURN_NONE;
        }
        ```
    10. `vim Modules/clinic/_ssl.c.h` 在`_ssl__SSLContext_enable_signed_cert_timestamps`后面添加
        ```
        PyDoc_STRVAR(_ssl__SSLContext_add_cert_compression_brotli__doc__,
        "add_cert_compression_brotli($self, /)\n"
        "--\n"
        "\n");

        #define _SSL__SSLCONTEXT_ADD_CERT_COMPRESSION_BROTLI_METHODDEF    \
            {"add_cert_compression_brotli", (PyCFunction)_ssl__SSLContext_add_cert_compression_brotli, METH_NOARGS, _ssl__SSLContext_add_cert_compression_brotli__doc__},

        static PyObject *
        _ssl__SSLContext_add_cert_compression_brotli_impl(PySSLContext *self);

        static PyObject *
        _ssl__SSLContext_add_cert_compression_brotli(PySSLContext *self, PyObject *Py_UNUSED(ignored))
        {
            return _ssl__SSLContext_add_cert_compression_brotli_impl(self);
        }
        ```
    11. `vim Modules/_ssl.c` 在 `static struct PyMethodDef context_methods[]` 添加 
        ```
        _SSL__SSLCONTEXT_ADD_CERT_COMPRESSION_BROTLI_METHODDEF
        ```
    12. python `vim Modules/_ssl.c` 在 `_ssl__SSLSocket_do_handshake_impl` 函数前面添加
        ```
        static PyObject *
        _ssl__SSLSocket_add_h2_application_settings_impl(PySSLSocket *self)
        {
            int ret = SSL_add_h2_application_settings(self->ssl);
            if (ret != 1) {
                ERR_clear_error();
                PyErr_SetString(PySSLErrorObject,
                                "add_h2_application_settings failed.");
                return NULL;
            }
            Py_RETURN_NONE;
        }
        ```
        在 `PySSLMethods` 里面添加
        ```
        _SSL__SSLSOCKET_ADD_H2_APPLICATION_SETTINGS_METHODDEF
        ```
    13. `vim Modules/clinic/_ssl.c.h` 随便找个地方添加
        ```
        PyDoc_STRVAR(_ssl__SSLSocket_add_h2_application_settings__doc__,
        "add_h2_application_settings($self, /)\n"
        "--\n"
        "\n");

        #define _SSL__SSLSOCKET_ADD_H2_APPLICATION_SETTINGS_METHODDEF    \
            {"add_h2_application_settings", (PyCFunction)_ssl__SSLSocket_add_h2_application_settings, METH_NOARGS, _ssl__SSLSocket_add_h2_application_settings__doc__},

        static PyObject *
        _ssl__SSLSocket_add_h2_application_settings_impl(PySSLSocket *self);

        static PyObject *
        _ssl__SSLSocket_add_h2_application_settings(PySSLSocket *self, PyObject *Py_UNUSED(ignored))
        {
            return _ssl__SSLSocket_add_h2_application_settings_impl(self);
        }
        ```
    14. python源码目录下 Lib/ssl.py 在
        ```
        self._sslobj = self._context._wrap_socket(
                self, server_side, self.server_hostname,
                owner=self, session=self._session,
            )
        ```后面添加`self._sslobj.add_h2_application_settings()`
    15. 编译python
        ```
        ./configure --with-openssl=/home/db/tls_python/boringssl --prefix=/home/db/tls_python/python
        ```
    16. `vim Modules/Setup`，找到SSL，修改为下面的内容
        ```
        SSL=/home/db/python_boringssl/boringssl
        _ssl _ssl.c \
            -DUSE_SSL -I$(SSL)/include -I$(SSL)/include/openssl \
            -L$(SSL)/lib -lssl -lcrypto
        ```
    17. `make CFLAGS="-Wno-error" && make install`
6. env
    1. application_layer_protocol_negotiation `vim env/lib/python3.8/site-packages/httpcore/_sync/connection.py` h2和http/1.1的顺序调换位置