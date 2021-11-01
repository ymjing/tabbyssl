/*
 * Copyright (c) 2019-2021, Yiming Jing
 * Copyright (c) 2017-2019, The MesaLink Authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except
 * in compliance with the License. You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <tabbyssl/ssl.h>
#include <unistd.h>

#define REQUEST                                                          \
  "GET / HTTP/1.0\r\nHost: %s\r\nConnection: close\r\nAccept-Encoding: " \
  "identity\r\n\r\n"

int tls_client(SSL_CTX *, const char *);

int tls_client(SSL_CTX *ctx, const char *hostname) {
  SSL *ssl = NULL;
  int sockfd = -1;
  struct hostent *hp;
  struct sockaddr_in addr;
  char sendbuf[8192] = {0};
  char recvbuf[8192] = {0};

  if ((hp = gethostbyname(hostname)) == NULL) {
    fprintf(stderr, "[-] Gethostname error\n");
    goto fail;
  }
  memset(&addr, 0, sizeof(addr));
  memmove(&addr.sin_addr, hp->h_addr, hp->h_length);
  addr.sin_family = AF_INET;
  addr.sin_port = htons(443);
  sockfd = socket(AF_INET, SOCK_STREAM, 0);
  if (connect(sockfd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
    fprintf(stderr, "[-] Connect error\n");
    goto fail;
  }
  ssl = SSL_new(ctx);
  if (ssl == NULL) {
    fprintf(stderr, "[-] Failed to create SSL\n");
    ERR_print_errors_fp(stderr);
    goto fail;
  }
  char hostname_buf[256] = {0};
  strncpy(hostname_buf, hostname, strlen(hostname));
  if (SSL_set_tlsext_host_name(ssl, hostname_buf) != SSL_SUCCESS) {
    fprintf(stderr, "[-] Failed to set hostname\n");
    goto fail;
  }
  if (SSL_set_fd(ssl, sockfd) != SSL_SUCCESS) {
    fprintf(stderr, "[-] Faield to set fd\n");
    goto fail;
  }
  if (SSL_connect(ssl) == SSL_SUCCESS) {
    int sendlen = -1, recvlen = -1, total_recvlen = 0;

    snprintf(sendbuf, sizeof(sendbuf), REQUEST, hostname);
    sendlen = SSL_write(ssl, sendbuf, (int)strlen(sendbuf));
    printf("[+] Sent %d bytes\n\n%s\n", sendlen, sendbuf);

    while ((recvlen = SSL_read(ssl, recvbuf, sizeof(recvbuf) - 1)) > 0) {
      recvbuf[recvlen] = 0;
      total_recvlen += strlen(recvbuf);
      printf("%s", recvbuf);
    };
    if (total_recvlen > 0) {
      const char *tls_version;
      if ((tls_version = SSL_get_version(ssl))) {
        printf("\n[+] TLS protocol version: %s\n", tls_version);
      }

      printf("\n[+] Received %d bytes\n", total_recvlen);
    } else {
      fprintf(stderr, "[-] Got nothing\n");
    }

    printf("[+] Negotiated ciphersuite: %s, version=%s\n",
           SSL_get_cipher_name(ssl), SSL_get_cipher_version(ssl));

    char name_buf[253] = {0};
    X509 *cert = SSL_get_peer_certificate(ssl);

    X509_NAME *tmp = X509_get_subject(cert);
    X509_NAME_free(tmp);

    X509_NAME *subject_name = X509_get_subject_name(cert);
    X509_NAME_oneline(subject_name, name_buf, 253);
    printf("[+] Subject name: %s\n", name_buf);
    X509_NAME_free(subject_name);
    memset(name_buf, 0, 253);

    STACK_X509_NAME *names = X509_get_alt_subject_names(cert);
    int length = sk_X509_NAME_num(names);
    printf("[+] Subject alternative names:");
    int i;
    for (i = 0; i < length; i++) {
      X509_NAME *name = sk_X509_NAME_value(names, i);
      printf("%s ", X509_NAME_oneline(name, name_buf, 253));
    }
    printf("\n");
    sk_X509_NAME_free(names);
    X509_free(cert);
  } else {
    fprintf(stderr, "[-] Socket not connected\n");
    fprintf(stderr, "[-] SSL error code: 0x%x\n", SSL_get_error(ssl, -1));
    ERR_print_errors_fp(stderr);
    goto fail;
  }
fail:

  if (ssl) {
    SSL_free(ssl);
  }
  if (!sockfd) {
    close(sockfd);
  }
  return -1;
}

int main(int argc, char *argv[]) {
  const char *hostname;
  SSL_CTX *ctx;

  if (argc != 2) {
    printf("Usage: %s <hostname>\n", argv[0]);
    exit(0);
  }
  hostname = argv[1];
  SSL_library_init();
  OpenSSL_add_ssl_algorithms();
  // SSL_load_error_strings(); // Uncomment this line to see SSL logs

  ctx = SSL_CTX_new(SSLv23_client_method());

  if (ctx == NULL) {
    fprintf(stderr, "[-] Failed to create SSL_CTX\n");
    ERR_print_errors_fp(stderr);
    return -1;
  }

  tls_client(ctx, hostname);
  SSL_CTX_free(ctx);
  return 0;
}