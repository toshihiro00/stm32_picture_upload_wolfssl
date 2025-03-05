/* server-tls-uart-picture.c
 *
 * Copyright (C) 2006-2021 wolfSSL Inc.
 *
 * This file is part of wolfSSL. (formerly known as CyaSSL)
 *
 * wolfSSL is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * wolfSSL is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA
 *
 *=============================================================================
 *
 * Example for TLS server over UART
 */


#define _XOPEN_SOURCE 600
#include <stdio.h>                  /* standard in/out procedures */
#include <stdlib.h>                 /* defines system calls */
#include <string.h>                 /* necessary for memset */
#include <netdb.h>
#include <sys/socket.h>             /* used for all socket calls */
#include <netinet/in.h>             /* used for sockaddr_in6 */
#include <arpa/inet.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <termios.h>
#include <signal.h>
#include <errno.h>

#ifndef WOLFSSL_USER_SETTINGS
    #include <wolfssl/options.h>
#endif
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/ssl.h>
#include <wolfssl/wolfcrypt/wc_port.h>

#define CERT_FILE "../../../certs/server-cert.pem"
#define KEY_FILE  "../../../certs/server-key.pem"

/* build with:
gcc -lwolfssl -o server-tls-uart server-tls-uart.c
*/

#ifndef UART_DEV
    #ifdef __MACH__
        #define UART_DEV "/dev/cu.usbmodem14502"
    #else
        #define UART_DEV "/dev/ttyUSB0"
    #endif
#endif
#ifndef B115200
#define B115200 115200
#endif

#define LOCAL_HOST "127.0.0.1"
#define DEFALUT_PORT 11111

/* Max buffer for a single TLS frame */
#ifndef MAX_RECORD_SIZE
#define MAX_RECORD_SIZE (1000 * 1024)
#endif

typedef struct CbCtx {
    int portFd;
    byte buf[MAX_RECORD_SIZE];
    int pos;
} CbCtx_t;


typedef enum tagBASE64_TYPE {
	BASE64_TYPE_STANDARD,
	BASE64_TYPE_MIME,
	BASE64_TYPE_URL
} BASE64_TYPE;

char *base64Encode(const char *data, const size_t size, const BASE64_TYPE type);
char *base64Decode(const char *base64, size_t *retSize, const BASE64_TYPE type);


static const char BASE64_TABLE[] = {
	"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
};
static const char BASE64_TABLE_URL[] = {
	"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
};
static const int BASE64_TABLE_LENGTH = {
	sizeof(BASE64_TABLE) / sizeof(BASE64_TABLE[0]) - 1
};

typedef struct tagBASE64_SPEC {
	BASE64_TYPE type;
	const char *table;
	char pad;
	int maxLineLength;
	char *lineSep;
	int lineSepLength;
} BASE64_SPEC;
static const BASE64_SPEC BASE64_SPECS[] = {
	{ BASE64_TYPE_STANDARD, BASE64_TABLE,     '=', 0,  NULL,   0 },
	{ BASE64_TYPE_MIME,     BASE64_TABLE,     '=', 76, "\r\n", 2 },
	{ BASE64_TYPE_URL,      BASE64_TABLE_URL, 0,   0,  NULL,   0 }
};
static const size_t BASE64_SPECS_LENGTH = {
	sizeof(BASE64_SPECS) / sizeof(BASE64_SPECS[0])
};

char *base64Encode(const char *data, const size_t size, const BASE64_TYPE type)
{
	BASE64_SPEC spec;
	size_t length;
	char *base64;
	char *cursor;
	int lineLength;
	int i;
	int j;

	if (data == NULL) {
		return NULL;
	}

	spec = BASE64_SPECS[0];
	for (i = 0; i < (int)BASE64_SPECS_LENGTH; i++) {
		if (BASE64_SPECS[i].type == type) {
			spec = BASE64_SPECS[i];
			break;
		}
	}

	length = size * 4 / 3 + 3 + 1;
	if (spec.maxLineLength > 0) {
		length += size / spec.maxLineLength * spec.lineSepLength;
	}
	base64 = malloc(length);
	if (base64 == NULL) {
		return NULL;
	}

	cursor = base64;
	lineLength = 0;
	for (i = 0, j = size; j > 0; i += 3, j -= 3) {
		if (spec.maxLineLength > 0) {
			if (lineLength >= spec.maxLineLength) {
				char *sep;

				for (sep = spec.lineSep; *sep != 0; sep++) {
					*(cursor++) = *sep;
				}
				lineLength = 0;
			}
			lineLength += 4;
		}

		if (j == 1) {
			*(cursor++) = spec.table[(data[i + 0] >> 2 & 0x3f)];
			*(cursor++) = spec.table[(data[i + 0] << 4 & 0x30)];
			*(cursor++) = spec.pad;
			*(cursor++) = spec.pad;
		}
		else if (j == 2) {
			*(cursor++) = spec.table[(data[i + 0] >> 2 & 0x3f)];
			*(cursor++) = spec.table[(data[i + 0] << 4 & 0x30) | (data[i + 1] >> 4 & 0x0f)];
			*(cursor++) = spec.table[(data[i + 1] << 2 & 0x3c)];
			*(cursor++) = spec.pad;
		}
		else {
			*(cursor++) = spec.table[(data[i + 0] >> 2 & 0x3f)];
			*(cursor++) = spec.table[(data[i + 0] << 4 & 0x30) | (data[i + 1] >> 4 & 0x0f)];
			*(cursor++) = spec.table[(data[i + 1] << 2 & 0x3c) | (data[i + 2] >> 6 & 0x03)];
			*(cursor++) = spec.table[(data[i + 2] << 0 & 0x3f)];
		}
	}
	*cursor = 0;

	return base64;
}

char *base64Decode(const char *base64, size_t *retSize, const BASE64_TYPE type)
{
	BASE64_SPEC spec;
	char table[0x80];
	size_t length;
	char *data;
	char *cursor;
	int i;
	int j;

	if (base64 == NULL) {
		return NULL;
	}

	spec = BASE64_SPECS[0];
	for (i = 0; i < (int)BASE64_SPECS_LENGTH; i++) {
		if (BASE64_SPECS[i].type == type) {
			spec = BASE64_SPECS[i];
			break;
		}
	}

	length = strlen(base64);
	data = malloc(length * 3 / 4 + 2 + 1);
	if (data == NULL) {
		return NULL;
	}

	memset(table, 0x80, sizeof(table));
	for (i = 0; i < BASE64_TABLE_LENGTH; i++) {
		table[spec.table[i] & 0x7f] = i;
	}

	cursor = data;
	for (i = 0, j = 0; i < (int)length; i++, j = i % 4) {
		char ch;

		if (base64[i] == spec.pad) {
			break;
		}

		ch = table[base64[i] & 0x7f];
		if (ch & 0x80) {
			continue;
		}
		if (j == 0) {
			*cursor = ch << 2 & 0xfc;
		}
		else if (j == 1) {
			*(cursor++) |= ch >> 4 & 0x03;
			*cursor = ch << 4 & 0xf0;
		}
		else if (j == 2) {
			*(cursor++) |= ch >> 2 & 0x0f;
			*cursor = ch << 6 & 0xc0;
		}
		else {
			*(cursor++) |= ch & 0x3f;
		}
	}
	*cursor = 0;
	*retSize = cursor - data;

	return data;
}

static int uartIORx(WOLFSSL *ssl, char *buf, int sz, void *ctx)
{
    int ret, recvd = 0;
    CbCtx_t* cbCtx = (CbCtx_t*)ctx;

#ifdef DEBUG_UART_IO
    printf("UART Read: In %d\n", sz);
#endif

    /* Is there pending data, return it */
    if (cbCtx->pos > 0) {
        recvd = cbCtx->pos;
        if (recvd > sz)
            recvd = sz;
        XMEMCPY(buf, cbCtx->buf, recvd);
        XMEMCPY(cbCtx->buf, cbCtx->buf + recvd, cbCtx->pos - recvd);
        cbCtx->pos -= recvd;
    }

    if (recvd < sz && cbCtx->pos == 0) {
        int avail, remain;

        /* Read remain */
        do {
            remain = sz - recvd;
            ret = read(cbCtx->portFd, buf + recvd, remain);
            if (ret > 0) {
                recvd += ret;
            }
        } while (ret >= 0 && recvd < sz);

        /* Read until 0 or out of space */
        do {
            avail = (int)sizeof(cbCtx->buf) - cbCtx->pos;
            ret = read(cbCtx->portFd, cbCtx->buf + cbCtx->pos, avail);
            if (ret > 0)
                cbCtx->pos += ret;
        } while (ret > 0);
    }

    if (recvd == 0) {
        recvd = WOLFSSL_CBIO_ERR_WANT_READ;
    }

#ifdef DEBUG_UART_IO
    printf("UART Read: Out %d\n", recvd);
#endif

    return recvd;
}

static int uartIOTx(WOLFSSL *ssl, char *buf, int sz, void *ctx)
{
    int sent;
    CbCtx_t* cbCtx = (CbCtx_t*)ctx;

#ifdef DEBUG_UART_IO
    printf("UART Write: In %d\n", sz);
#endif
    sent = write(cbCtx->portFd, buf, sz);
    if (sent == 0) {
        return WOLFSSL_CBIO_ERR_WANT_WRITE;
    }

#ifdef DEBUG_UART_IO
    printf("UART Write: Out %d\n", sent);
#endif

    return sent;
}

int main(int argc, char** argv)
{
    int ret = -1, err;
    WOLFSSL_CTX* ctx = NULL;
    WOLFSSL* ssl = NULL;
    CbCtx_t cBctx;
    struct termios tty;
    byte echoBuffer[400000];
    const char* uartDev = UART_DEV;

    /* Base64変換された画像ファイルIOするためのファイルポインタ定義 */
    FILE *fp;

    if (argc >= 2) {
        uartDev = argv[1];
    }

    /* Open UART file descriptor */
    XMEMSET(&cBctx, 0, sizeof(cBctx));
    cBctx.portFd = open(uartDev, O_RDWR | O_NOCTTY);
    if (cBctx.portFd < 0) {
        printf("Error opening %s: Error %i (%s)\n",
            uartDev, errno, strerror(errno));
        ret = errno;
        goto done;
    }
    tcgetattr(cBctx.portFd, &tty);
    cfsetospeed(&tty, B115200);
    cfsetispeed(&tty, B115200);
    tty.c_cflag = (tty.c_cflag & ~CSIZE) | (CS8);
    tty.c_iflag &= ~(IGNBRK | IXON | IXOFF | IXANY| INLCR | ICRNL);
    tty.c_oflag &= ~OPOST;
    tty.c_oflag &= ~(ONLCR|OCRNL);
    tty.c_cflag &= ~(PARENB | PARODD | CSTOPB);
    tty.c_lflag &= ~(ICANON | ECHO | ECHOE | ISIG);
    tty.c_iflag &= ~ISTRIP;
    tty.c_cc[VMIN] = 0;
    tty.c_cc[VTIME] = 5;
    tcsetattr(cBctx.portFd, TCSANOW, &tty);

    /* Flush any data in the RX buffer */
    ret = read(cBctx.portFd, echoBuffer, sizeof(echoBuffer));
    if (ret < 0) {
        /* Ignore RX error on flush */
    }

#if 0
    wolfSSL_Debugging_ON();
#endif

    ctx = wolfSSL_CTX_new(wolfTLSv1_3_server_method());
    if (ctx == NULL) {
        printf("Error creating WOLFSSL_CTX\n");
        goto done;
    }

    /* Register wolfSSL send/recv callbacks */
    wolfSSL_CTX_SetIOSend(ctx, uartIOTx);
    wolfSSL_CTX_SetIORecv(ctx, uartIORx);

    /* For testing disable peer cert verification; the focus is on key
     * establishment via post-quantum KEM. */
    wolfSSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);

    /* Set server key and certificate (required) */
    if ((ret = wolfSSL_CTX_use_certificate_file(ctx, CERT_FILE, SSL_FILETYPE_PEM)) != WOLFSSL_SUCCESS) {
        fprintf(stderr, "ERROR: failed to load %s, please check the file.\n", CERT_FILE);
        goto done;
    }

    if ((ret = wolfSSL_CTX_use_PrivateKey_file(ctx, KEY_FILE, SSL_FILETYPE_PEM)) != WOLFSSL_SUCCESS) {
        fprintf(stderr, "ERROR: failed to load %s, please check the file.\n", KEY_FILE);
        goto done;
    }

    ssl = wolfSSL_new(ctx);
    if (ssl == NULL) {
        printf("Error creating WOLFSSL\n");
        goto done;
    }

    /* Register wolfSSL read/write callback contexts */
    wolfSSL_SetIOReadCtx(ssl, &cBctx);
    wolfSSL_SetIOWriteCtx(ssl, &cBctx);

	/* クライアントとのTLS接続 */
    printf("Waiting for client\n");
    do {
        ret = wolfSSL_accept(ssl);
        err = wolfSSL_get_error(ssl, ret);
    } while (err == WOLFSSL_ERROR_WANT_READ || err == WOLFSSL_ERROR_WANT_WRITE);
    if (ret != WOLFSSL_SUCCESS) {
        printf("TLS accept error %d\n", err);
        goto done;
    }

    printf("TLS Accept handshake done\n");

    /* 平文で画像データの取得 */
    XMEMSET(echoBuffer, 0, sizeof(echoBuffer));
    do {
        ret = wolfSSL_read(ssl, echoBuffer, sizeof(echoBuffer)-1);
        err = wolfSSL_get_error(ssl, ret);
    } while (err == WOLFSSL_ERROR_WANT_READ || err == WOLFSSL_ERROR_WANT_WRITE);
//    printf("Read (%d): %s\n", err, echoBuffer);

    size_t size = 0;
    char *data = base64Decode(echoBuffer, &size, BASE64_TYPE_STANDARD);

    char filename[100];
    sprintf(filename, "recv_data_%d.jpg",size);
    fp = fopen(filename,"w");

    printf("Picture Data Size: %d [byte]\n", size);

    for(int i=0; i < size; i++)
    {
        fprintf(fp, "%c", data[i]);
    }

    fclose(fp);

   ret = 0; /* Success */

done:
    if (ssl) {
        wolfSSL_shutdown(ssl);
        wolfSSL_free(ssl);
    }
    if (ctx) {
        wolfSSL_CTX_free(ctx);
    }

    if (cBctx.portFd >= 0)
        close(cBctx.portFd);

    return ret;
}
