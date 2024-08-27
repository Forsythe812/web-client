#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <unistd.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#define MAX_REDIRECTS 5
#define BUFFER_SIZE 4096

#define SUCCESS      0
#define ERR_PARAM   -1
#define ERR_URL     -2

int parse_url(const char *url, char *hostname, char *path){
    if (url == NULL || hostname == NULL || path == NULL){
        return ERR_PARAM;
    }
    // parse host from url
    const char *host_start = strstr(url,"//");
    if (host_start){
        host_start += 2;
    } else{
        host_start = url;
    }

    // parse path from url
    const char *path_start = strchr(host_start, '/');
    if (path_start){
        strncpy(hostname, host_start, path_start - host_start);
        hostname[path_start - host_start] = '\0';
        strcpy(path,path_start);
    } else{
        strcpy(hostname, host_start);
        strcpy(path, "/");
    } 

    return SUCCESS;
}

int is_https (const char *url, char *hostname, char *path, char *request){
    if (strncmp(url, "https://",8) == 0){
        snprintf(request, BUFFER_SIZE, "GET %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", path, hostname);
        return 1;
    } else if (strncmp(url, "http://",7) == 0){
        snprintf(request, BUFFER_SIZE, "GET %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", path, hostname);
        return 0;
    } else {
        fprintf(stderr, "Invalid URL format\n");
        return ERR_URL;
    }
}

int main (){

    char hostname[BUFFER_SIZE];
    char path[BUFFER_SIZE];
    char request[BUFFER_SIZE];
    char response[BUFFER_SIZE];
    FILE *file;

    int status;
    int sockfd;
    int bytes_received;
    struct addrinfo hints, *res, *p;

    int use_ssl = 0;
    SSL_CTX *ctx = NULL;
    SSL *ssl = NULL;

    char *url = "https://www.openfind.com.tw/taiwan/";

    // step 1 : parse url
    parse_url(url, hostname, path);

    printf("Hostname : %s\n",hostname);
    printf("Path : %s\n",path);

    // step 2 : check if http or https to use ssl
    if (strncmp(url, "https://", 8) == 0) {
        use_ssl = 1;
        snprintf(request, BUFFER_SIZE, "GET %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", path, hostname);
    } else if (strncmp(url, "http://", 7) == 0) {
        use_ssl = 0;
        snprintf(request, BUFFER_SIZE, "GET %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", path, hostname);
    } else {
        fprintf(stderr, "Invalid URL format\n");
        return ERR_URL;
    }

    // step 3 : prepare hints for getaddr
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    // step 4 : resolve the hostname
    if ((status = getaddrinfo(hostname, use_ssl ? "443" : "80", &hints, &res)) != 0) {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(status));
        return 1;
    }


    // step 5 : loop through result and connect to the first one
    for (p = res; p != NULL; p = p->ai_next) {
        sockfd = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (sockfd == -1) continue;

        if (connect(sockfd, p->ai_addr, p->ai_addrlen) == -1) {
            close(sockfd);
            continue;
        }

        break;
    }   

    if (p == NULL) {
        fprintf(stderr, "Failed to connect\n");
        return 1;
    }

    freeaddrinfo(res);

    file = fopen("response.html", "wb");
    if (!file) {
        perror("Failed to open file");
        close(sockfd);
        return 1;
    }

    // step 6: if https, use ssl connection
    if (use_ssl) {
        SSL_library_init();
        SSL_load_error_strings();
        OpenSSL_add_all_algorithms();
        ctx = SSL_CTX_new(TLS_client_method());

        if (ctx == NULL) {
            ERR_print_errors_fp(stderr);
            close(sockfd);
            return 1;
        }

        ssl = SSL_new(ctx);
        SSL_set_fd(ssl, sockfd);

        if (SSL_connect(ssl) <= 0) {
            ERR_print_errors_fp(stderr);
            SSL_free(ssl);
            SSL_CTX_free(ctx);
            close(sockfd);
            return 1;
        }

        // Step 7: Send HTTPS request
        printf("Sending HTTPS request...\n");
        SSL_write(ssl, request, strlen(request));

        printf("Receiving and writing response to file...\n");
        while ((bytes_received = SSL_read(ssl, response, BUFFER_SIZE - 1)) > 0) {
            response[bytes_received] = '\0';
            fwrite(response, 1, bytes_received, file);  // Write to file
        }
        
        /*
        // Step 8: Receive HTTPS response
        int bytes_received = SSL_read(ssl, response, BUFFER_SIZE - 1);
        if (bytes_received < 0) {
            fprintf(stderr, "Error reading SSL response\n");
        } else {
            response[bytes_received] = '\0';
            printf("Response:\n%s\n", response);
        }
        */

        SSL_shutdown(ssl);
        SSL_free(ssl);
        SSL_CTX_free(ctx);
    } else {
        // Step 7: Send HTTP request over plain TCP
        printf("Sending HTTP request...\n");
        send(sockfd, request, strlen(request), 0);

        printf("Receiving and writing response to file...\n");
        while ((bytes_received = recv(sockfd, response, BUFFER_SIZE - 1, 0)) > 0) {
            response[bytes_received] = '\0';
            fwrite(response, 1, bytes_received, file);  // Write to file
        }

        /*
        int bytes_received = recv(sockfd, response, BUFFER_SIZE - 1, 0);
        if (bytes_received < 0) {
            fprintf(stderr, "Error reading response\n");
        } else {
            response[bytes_received] = '\0';
            printf("Response:\n%s\n", response);
        }
        */
    }

    fclose(file);

    close(sockfd);

    return 0;
}