/*******************************************************************************
 * Copyright (c) 2014, 2017 IBM Corp.
 *
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * and Eclipse Distribution License v1.0 which accompany this distribution.
 *
 * The Eclipse Public License is available at
 *    http://www.eclipse.org/legal/epl-v10.html
 * and the Eclipse Distribution License is available at
 *   http://www.eclipse.org/org/documents/edl-v10.php.
 *
 * Contributors:
 *    Allan Stockdill-Mander - initial API and implementation and/or initial documentation
 *    Ian Craggs - return codes from linux_read
 *******************************************************************************/

#include "MQTTLinux.h"

#include <assert.h>
#include <stdarg.h> //va_start

static char *ms_vosGetCurrentDate(void)
{

	struct timeval tv;
	struct tm tm;
	static char s_dateStr[32];
	int len = 28;

	memset(&tv, 0, sizeof(tv));
	memset(&tm, 0, sizeof(tm));
	gettimeofday(&tv, NULL);
	localtime_r(&tv.tv_sec, &tm);
	strftime(s_dateStr, len, "%Y-%m-%d %H:%M:%S", &tm);

	len = strlen(s_dateStr);
	sprintf(s_dateStr + len, ".%-4.3d", (int)(tv.tv_usec / 1000));

	return s_dateStr;
}

#define DBG_PRINT(format, args...) do { \
    { \
        printf("[%s][MQMbed][INFO ]:[%s:%d]"format,ms_vosGetCurrentDate(), __FILE__, __LINE__, ##args); \
    }\
} while(0)


#define TLS_CA_CERTIFICATE_PATH "/etc/mosquitto/certs/ca.crt"

#define tlstrans_LOGERR(format, args...) fprintf(stderr, format, ##args)
#define tlstrans_LOGDEBUG(format, args...) _static_debug_print(stdout, format, 1, __FILE__, __LINE__, ##args)
#define tlstrans_LOG(format, args...) printf("[AD]:"format, ##args)
#define UNUSED_VAR(x) ((void)x)

static void _static_debug(void *ctx, int level,
						  const char *file, int line, const char *str)
{
	UNUSED_VAR(level);
	fprintf((FILE *)ctx, "%s:%04d: %s", file, line, str);
	fflush((FILE *)ctx);
}
//! @BUG: 1k buff is not small stack friendly.
static void _static_debug_print(void *ctx, int level, const char *file, int line, const char *format, ...)
{
	char buff[1024] = "";
	char *ostr = buff;
	va_list args, cnt_args;
	va_start(args, format);
	va_copy(cnt_args, args);
	int cnt = vsnprintf(NULL, 0, format, cnt_args);
	if (cnt > sizeof(buff) - 1)
	{
		ostr = (char *)malloc(cnt + 1);
		if (!ostr)
		{
			fputs("heap allocation failure in print\n", (FILE *)ctx);
			abort();
		}
	}
	vsnprintf(ostr, cnt + 1, format, args);
	va_end(args);
	_static_debug(ctx, level, file, line, ostr);
	if (ostr != buff)
		free(ostr);
}

void TimerInit(Timer* timer)
{
	timer->end_time = (struct timeval){0, 0};
}

char TimerIsExpired(Timer* timer)
{
	struct timeval now, res;
	gettimeofday(&now, NULL);
	timersub(&timer->end_time, &now, &res);
	return res.tv_sec < 0 || (res.tv_sec == 0 && res.tv_usec <= 0);
}


void TimerCountdownMS(Timer* timer, unsigned int timeout)
{
	struct timeval now;
	gettimeofday(&now, NULL);
	struct timeval interval = {timeout / 1000, (timeout % 1000) * 1000};
	timeradd(&now, &interval, &timer->end_time);
}


void TimerCountdown(Timer* timer, unsigned int timeout)
{
	struct timeval now;
	gettimeofday(&now, NULL);
	struct timeval interval = {timeout, 0};
	timeradd(&now, &interval, &timer->end_time);
}


int TimerLeftMS(Timer* timer)
{
	struct timeval now, res;
	gettimeofday(&now, NULL);
	timersub(&timer->end_time, &now, &res);
	//printf("left %d ms\n", (res.tv_sec < 0) ? 0 : res.tv_sec * 1000 + res.tv_usec / 1000);
	return (res.tv_sec < 0) ? 0 : res.tv_sec * 1000 + res.tv_usec / 1000;
}


int linux_read(Network* n, unsigned char* buffer, int len, int timeout_ms)
{
	struct timeval interval = {timeout_ms / 1000, (timeout_ms % 1000) * 1000};
	if (interval.tv_sec < 0 || (interval.tv_sec == 0 && interval.tv_usec <= 0))
	{
		interval.tv_sec = 0;
		interval.tv_usec = 100;
	}

	setsockopt(n->conn_ctx.fd, SOL_SOCKET, SO_RCVTIMEO, (char *)&interval, sizeof(struct timeval));

	int bytes = 0;
	while (bytes < len)
	{
		//int rc = recv(n->my_socket, &buffer[bytes], (size_t)(len - bytes), 0);
		int rc = mbedtls_ssl_read(&n->ssl, &buffer[bytes], (size_t)(len - bytes));

		if (rc <= -1) // wuhao == -> <=
		{
			char errbuf[256];
			if (rc == -0x4c)
			{ // seems to be what mbedtls_ssl_read provides when not expecting to timeout...
				bytes = 0;
				break;
			}
			mbedtls_strerror(rc, errbuf, sizeof(errbuf));
			tlstrans_LOGERR("[AD]mbedtls_ssl_read returned error -0x%x: %d,%s\n", -rc, (int)sizeof(errbuf), errbuf);
			bytes = -1;
			break;
		}
		else if (rc == 0)
		{
			bytes = 0;
			break;
		}
		else
		{
			bytes += rc;
			tlstrans_LOG("[timeout_ms:%d]linux_read:len=%d,rc=0x%x.\n", timeout_ms, len, rc);
		}
			
	}

	return bytes;
}


int linux_write(Network* n, unsigned char* buffer, int len, int timeout_ms)
{
	struct timeval tv;

	tlstrans_LOG("[timeout_ms:%d]linux_write:len=%d.\n", timeout_ms, len);

	tv.tv_sec = 0;  /* 30 Secs Timeout */
	tv.tv_usec = timeout_ms * 1000;  // Not init'ing this can cause strange errors

	setsockopt(n->conn_ctx.fd, SOL_SOCKET, SO_SNDTIMEO, (char *)&tv, sizeof(struct timeval));
	//int	rc = write(n->my_socket, buffer, len);
	if (timeout_ms == 0)
	{
		// if timeout_ms == 0, must handle partial writes on our own.
		// ref: https://tls.mbed.org/api/ssl_8h.html#a5bbda87d484de82df730758b475f32e5
		int rc = 0;
		while ((rc = mbedtls_ssl_write(&n->ssl, buffer, len)) >= 0)
		{
			assert(rc <= len); // can this be greater than? what does that mean?
			if (rc >= len)
				break;
			buffer += rc;
			len -= rc;
		}
		if (rc < 0)
			return rc;
		return len;
	}
	else
	{
		return mbedtls_ssl_write(&n->ssl, buffer, len);
	}
}


void NetworkInit(Network* n)
{
	n->mqttread = linux_read;
	n->mqttwrite = linux_write;

	mbedtls_net_init(&n->conn_ctx);

	mbedtls_ssl_init(&n->ssl);
	mbedtls_ssl_config_init(&n->conf);
	mbedtls_x509_crt_init(&n->cacert);
	mbedtls_ctr_drbg_init(&n->ctr_drbg);
	mbedtls_entropy_init(&n->entropy);

	mbedtls_x509_crt_parse_file(&n->cacert, TLS_CA_CERTIFICATE_PATH); //! @BUG: Remove hardcoded path
}

int NetworkConnect(Network *n, char *hostname, int port)
{
	assert(port > 0 && port < USHRT_MAX);
	char port_str[6];
	snprintf(port_str, sizeof(port_str), "%d", port); //! @TODO: itoa() instead?
	const char *FUNC_NAME = "";

	int rc = -1;

	// Can provide personalization identifier in arg 4 & 5 for more entropy.
	FUNC_NAME = "mbedtls_ctr_drbg_seed";
	if ((rc = mbedtls_ctr_drbg_seed(&n->ctr_drbg, mbedtls_entropy_func, &n->entropy,
									(const unsigned char *)NULL,
									0)) != 0)
		goto error_out;

	/*
	 * Start the connection
	 */
	tlstrans_LOG("-Connecting to tcp/%s/%s...", hostname, port_str);
	fflush(stdout);

	FUNC_NAME = "mbedtls_net_connect";
	if ((rc = mbedtls_net_connect(&n->conn_ctx, hostname,
								  port_str, MBEDTLS_NET_PROTO_TCP)) != 0)
		goto error_out;
	tlstrans_LOG("ok\n");

	FUNC_NAME = "mbedtls_ssl_config_defaults";
	if ((rc = mbedtls_ssl_config_defaults(&n->conf,
										  MBEDTLS_SSL_IS_CLIENT,
										  MBEDTLS_SSL_TRANSPORT_STREAM,
										  MBEDTLS_SSL_PRESET_DEFAULT)) != 0)
		goto error_out;

	mbedtls_ssl_conf_authmode(&n->conf, MBEDTLS_SSL_VERIFY_OPTIONAL); //! @BUG: NO SECURITY.
	mbedtls_ssl_conf_ca_chain(&n->conf, &n->cacert, NULL);			// should only be set if VERIFY OPTIONAL or REQUIRED.

	mbedtls_ssl_conf_rng(&n->conf, mbedtls_ctr_drbg_random, &n->ctr_drbg);
	mbedtls_ssl_conf_dbg(&n->conf, _static_debug, stdout); // debug callback defined above.

	FUNC_NAME = "mbedtls_ssl_setup";
	if ((rc = mbedtls_ssl_setup(&n->ssl, &n->conf)) != 0)
		goto error_out;

	FUNC_NAME = "mbedtls_ssl_set_hostname";
#if defined(TLS_NONSTANDARD_SERVER_CN)
	if ((rc = mbedtls_ssl_set_hostname(&n->ssl, TLS_NONSTANDARD_SERVER_CN)) != 0) //! @BUG: hardcoded CN
		goto error_out;
#else
	if ((rc = mbedtls_ssl_set_hostname(&n->ssl, hostname)) != 0) //! @TODO: Verify this is necessary and not default behavior.
		goto error_out;
#endif

	mbedtls_ssl_set_bio(&n->ssl, &n->conn_ctx, mbedtls_net_send, mbedtls_net_recv, NULL);

	/*
	 * 4. TLS Handshake and verification
	 */
	tlstrans_LOG("-Performing the SSL/TLS handshake...");
	fflush(stdout);
	FUNC_NAME = "mbedtls_ssl_handshake";
	while ((rc = mbedtls_ssl_handshake(&n->ssl)) != 0)
	{
		if (rc != MBEDTLS_ERR_SSL_WANT_READ && rc != MBEDTLS_ERR_SSL_WANT_WRITE)
			goto error_out;
	}

	tlstrans_LOG("success (%d).\n", rc);

	rc = mbedtls_ssl_get_verify_result(&n->ssl); //! @BUG: if this is non-zero, it should abort. Maybe instead use VERIFY_REQUIRED?
	tlstrans_LOG("CN verify result: %d\n", rc);

	return 0;
error_out:
	tlstrans_LOGERR("[NetworkConnect]failed\n  ! %s returned %d\n", FUNC_NAME, rc);
	return rc;
}

void NetworkDisconnect(Network* n)
{
	//close(n->my_socket);
	mbedtls_net_free(&n->conn_ctx);
}

void NetworkExit(Network *n)
{
	mbedtls_x509_crt_free(&n->cacert);
	mbedtls_ssl_free(&n->ssl);
	mbedtls_ssl_config_free(&n->conf);
	mbedtls_ctr_drbg_free(&n->ctr_drbg);
	mbedtls_entropy_free(&n->entropy);
}