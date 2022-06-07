# 使用场景
1. macos环境
2. iOS 14_2 6s手机 oc_tls
3. python-3.8.9 源码
4. boringssl 就按照目录下的

## 编译步骤
1. 安装必须的包
    1. brew install golang cmake xz libx11 zlib
    2. 设置go的加速镜像
        ```
        go env -w GO111MODULE=on
        go env -w GOPROXY=https://mirrors.aliyun.com/goproxy/,direct
        ```
2. boringssl
    1. `vim include/openssl/ssl.h` 在`#define SSL_VERIFY_PEER_IF_NO_OBC 0x04`后面添加 `#define SSL_VERIFY_POST_HANDSHAKE 0x08`
    2. 添加 ciphers
        1. `vim ssl/ssl_cipher.cc` 在 `static constexpr SSL_CIPHER kCiphers`里面添加
            ```
            /* Cipher C023 */
            {
                TLS1_TXT_ECDHE_ECDSA_WITH_AES_128_SHA256,
                "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256",
                TLS1_CK_ECDHE_ECDSA_WITH_AES_128_SHA256,
                SSL_kECDHE,
                SSL_aECDSA,
                SSL_AES128,
                SSL_SHA256,
                SSL_HANDSHAKE_MAC_SHA256,
            },

            /* Cipher C024 */
            {
                TLS1_TXT_ECDHE_ECDSA_WITH_AES_256_SHA384,
                "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384",
                TLS1_CK_ECDHE_ECDSA_WITH_AES_256_SHA384,
                SSL_kECDHE,
                SSL_aECDSA,
                SSL_AES256,
                SSL_SHA384,
                SSL_HANDSHAKE_MAC_SHA384,
            },

            /* Cipher C027 */
            {
                TLS1_TXT_ECDHE_RSA_WITH_AES_128_SHA256,
                "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256",
                TLS1_CK_ECDHE_RSA_WITH_AES_128_SHA256,
                SSL_kECDHE,
                SSL_aRSA,
                SSL_AES128,
                SSL_SHA256,
                SSL_HANDSHAKE_MAC_SHA256,
            },

            /* Cipher C028 */
            {
                TLS1_TXT_ECDHE_RSA_WITH_AES_256_SHA384,
                "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384",
                TLS1_CK_ECDHE_RSA_WITH_AES_256_SHA384,
                SSL_kECDHE,
                SSL_aRSA,
                SSL_AES256,
                SSL_SHA384,
                SSL_HANDSHAKE_MAC_SHA384,
            },
            ```
        2. `vim ssl/internal.h` 在 `#define SSL_SHA1 0x00000001u` 后面添加
            ```
            #define SSL_SHA256 0x00000010L
            #define SSL_SHA384 0x00000020L
            ```
    3. `supported_groups` 里面添加 `Supported Group: secp521r1 (0x0019)` 
        1. 在 `ssl/extensions.cc`的`static const uint16_t kDefaultGroups` 里面添加`SSL_CURVE_SECP521R1`
    4. 多了的session_ticket 注释掉
        ```
        {
          TLSEXT_TYPE_session_ticket,
          ext_ticket_add_clienthello,
          ext_ticket_parse_serverhello,
          // Ticket extension client parsing is handled in ssl_session.c
          ignore_parse_clienthello,
          ext_ticket_add_serverhello,
        },

        ext_ticket_add_clienthello 方法
        ext_ticket_parse_serverhello 方法
        ext_ticket_add_serverhello 方法
        ```
    5. signature_algorithms修改 在 `ssl/extensions.cc`的kVerifySignatureAlgorithms修改为下面的
        ```
        static const uint16_t kVerifySignatureAlgorithms[] = {
            // List our preferred algorithms first.
            SSL_SIGN_ECDSA_SECP256R1_SHA256,
            SSL_SIGN_RSA_PSS_RSAE_SHA256,
            SSL_SIGN_RSA_PKCS1_SHA256,

            // Larger hashes are acceptable.
            SSL_SIGN_ECDSA_SECP384R1_SHA384,
            SSL_SIGN_ECDSA_SHA1,
            SSL_SIGN_RSA_PSS_RSAE_SHA384,
            SSL_SIGN_RSA_PSS_RSAE_SHA384,
            SSL_SIGN_RSA_PKCS1_SHA384,

            SSL_SIGN_RSA_PSS_RSAE_SHA512,
            SSL_SIGN_RSA_PKCS1_SHA512,

            // For now, SHA-1 is still accepted but least preferable.
            SSL_SIGN_RSA_PKCS1_SHA1,
        };
        ```
    6. supported_versions 去掉1.0 1.1 `vim ssl/ssl_versions.cc` 注释掉 `static const uint16_t kTLSVersions` 里面的 `TLS1_1_VERSION` 和 `TLS1_VERSION`
    7. `mkdir build && cd build && cmake ../ && make && cd ../`
    8. `mkdir -p .openssl/lib && cd .openssl && ln -s ../include . && cd ../`
    9. `cp build/crypto/libcrypto.a build/ssl/libssl.a .openssl/lib`
    10. `cp -R .openssl/lib ./`
3. python
    1. `vim Modules/_ssl.c` 注释掉下面的，是根据openssl的版本判断是否可以添加OPENSSL_KEYLOG。
        ```
        // #if (OPENSSL_VERSION_NUMBER >= 0x10101000L) && !defined(LIBRESSL_VERSION_NUMBER)
        // #define HAVE_OPENSSL_KEYLOG 1
        // #endif
        ```
    2. `vim Modules/_ssl.c` 注释掉下面的，这是tls1.3的，目前用不到，暂时先注释掉，用到tls1.3的时候，可以看看用boringssl的SSL_process_quic_post_handshake来代替可不可以
        ```
        SSL_set_post_handshake_auth(self->ssl, 1);
        ```
    3. `vim Modules/_ssl.c` 注释掉下面的，这是tls1.3的，目前用不到，暂时先注释掉，用到tls1.3的时候，再看怎么弄
        ```
        int err = SSL_verify_client_post_handshake(self->ssl);
        if (err == 0)
            return _setSSLError(NULL, 0, __FILE__, __LINE__);
        else

        SSL_CTX_set_post_handshake_auth(self->ctx, self->post_handshake_auth);
        ```
    4. `vim Modules/_ssl.c` 注释掉set_num_tickets有关的还有get_num_tickets有关的
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
    5. 添加grease
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
    6. status_request 添加
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
    8. 进入python根目录
        ```
        ./configure --with-openssl=/Users/xx/Documents/xxxx/python_with_tls/iOS_14_2_6s_oc_tls_python_boringssl/boringssl --prefix=/Users/xx/Documents/xxxx/python_with_tls/iOS_14_2_6s_oc_tls_python_boringssl/python
        ```
    9. `vim Modules/Setup`，找到SSL，修改为下面的内容
        ```
        SSL=/Users/xx/Documents/xxxx/python_with_tls/iOS_14_2_6s_oc_tls_python_boringssl/boringssl
        _ssl _ssl.c \
            -DUSE_SSL -I$(SSL)/include -I$(SSL)/include/openssl \
            -L$(SSL)/lib -lssl -lcrypto
        ```
    10. `make CFLAGS="-Wno-error" && make install`
4. 使用
    1. 在 `/Users/xx/Documents/xxxx/python_with_tls/iOS_14_2_6s_oc_tls_python_boringssl/python/bin`目录下`./pip3 install virtualenv -i https://pypi.douban.com/simple`
    2. 在 `/Users/xx/Documents/xxxx/python_with_tls/iOS_14_2_6s_oc_tls_python_boringssl/test`目录下`../python/bin/virtualenv -p ../python/bin/python3 env`
    3. 在 `/Users/xx/Documents/xxxx/python_with_tls/iOS_14_2_6s_oc_tls_python_boringssl/test`目录下`. env/bin/activate`
    4. 在 `/Users/xx/Documents/xxxx/python_with_tls/iOS_14_2_6s_oc_tls_python_boringssl/test`目录下`pip install httpx[http2] -i https://pypi.douban.com/simple`
    5. application_layer_protocol_negotiation 里面的顺序问题，直接在`/Users/xx/Documents/xxxx/python_with_tls/iOS_14_2_6s_oc_tls_python_boringssl/test`目录下修改 `vim env/lib/python3.8/site-packages/httpcore/_sync/connection.py` 42行，h2和http/1.1的顺序调换位置
5. 测试脚本
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
            "ECDHE-ECDSA-AES256-GCM-SHA384",
            "ECDHE-ECDSA-AES128-GCM-SHA256",
            "ECDHE-ECDSA-CHACHA20-POLY1305",
            "ECDHE-RSA-AES256-GCM-SHA384",
            "ECDHE-RSA-AES128-GCM-SHA256",
            "ECDHE-RSA-CHACHA20-POLY1305",
            "ECDHE-ECDSA-AES256-SHA384",
            "ECDHE-ECDSA-AES128-SHA256",
            "ECDHE-ECDSA-AES256-SHA",
            "ECDHE-ECDSA-AES128-SHA",
            "ECDHE-RSA-AES256-SHA384",
            "ECDHE-RSA-AES128-SHA256",
            "ECDHE-RSA-AES256-SHA",
            "ECDHE-RSA-AES128-SHA"
        ]
    )
    ssl_context.set_ciphers(CIPHERS)
    ssl_context.set_grease_enabled(True)
    ssl_context.enable_signed_cert_timestamps()
    ssl_context.enable_ocsp_stapling()
    #ssl_context.add_cert_compression_brotli()
    client = httpx.Client(http2=True, verify=ssl_context)

    headers = {
        "user-agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.77 Safari/537.36"
    }

    response = client.get("https://www.baidu.com", headers=headers)

    print(response.http_version)
    ```