#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <netdb.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <errno.h>
#include <regex.h>

#define MAX_REDIRECTS 5
#define BUFFER_SIZE 8192
#define MAX_CONCURRENT_CHILDREN 10
#define INITIAL_ARRAY_SIZE 100
#define MAX_CRAWL_DEPTH 1

#define SUCCESS          0
#define ERR_BASE         0
#define ERR_PARAM       (ERR_BASE-1)
#define ERR_URL         (ERR_BASE-2)
#define ERR_CONNECT     (ERR_BASE-3)
#define ERR_SSL         (ERR_BASE-4)
#define ERR_REDIRECT    (ERR_BASE-5)
#define ERR_FILE        (ERR_BASE-6)
#define ERR_GAI         (ERR_BASE-7)
#define ERR_STAT_CODE   (ERR_BASE-8)
#define ERR_MKDIR       (ERR_BASE-9)
#define ERR_SHM_OPEN    (ERR_BASE-10)
#define ERR_SHM_MAP     (ERR_BASE-11)
#define ERR_SHM_UNLINK  (ERR_BASE-12)
#define ERR_FORK        (ERR_BASE-13)
#define ERR_WAIT        (ERR_BASE-14)

#define MAX_URLS 100
#define MAX_URL_LENGTH 1024

typedef struct {
    char crawled_urls[MAX_URLS][MAX_URL_LENGTH];
    int crawled_count;
    int status[MAX_URLS]; // 0: not_crawled, 1: can_crawl, 2: crawling, 3: crawled
    int depth[MAX_URLS];
} CrawledData;

CrawledData *crawled_data;
char base_url[BUFFER_SIZE] = {0};

// Function prototypes
int fetch_url(const char *url, char *response, FILE *file, int *is_redirect, char *redirect_location);
int rebuild_url(const char *current_url, const char *redirect_location, char *new_url);
int already_crawled(CrawledData *data, const char *url);
void build_crawled_data(CrawledData *data, const char *filename, int depth);
void child_process(CrawledData *crawled_data, const char *url, int child_id, int depth);

void log_url_and_file(const char *url, const char *filename) {
    FILE *log_file = fopen("url_log.txt", "a");
    if (log_file == NULL) {
        perror("Failed to open log file");
        return;
    }
    fprintf(log_file, "URL: %s -> File: %s\n", url, filename);
    fclose(log_file);
}

int get_url_content(const char *url, const char *output_file) {
    char current_url[BUFFER_SIZE];
    strncpy(current_url, url, BUFFER_SIZE);
    current_url[BUFFER_SIZE - 1] = '\0';

    char response[BUFFER_SIZE];
    char redirect_location[BUFFER_SIZE];
    char new_url[BUFFER_SIZE];
    int is_redirect;
    int redirect_count = 0;

    FILE *file = fopen(output_file, "wb");
    if (!file) {
        perror("Failed to open file");
        return ERR_FILE;
    }

    do {
        is_redirect = 0;
        printf("Fetching URL: %s\n", current_url);
        int fetch_result = fetch_url(current_url, response, file, &is_redirect, redirect_location);
        if (fetch_result != SUCCESS) {
            fprintf(stderr, "Error fetching URL: %d\n", fetch_result);
            fclose(file);
            return fetch_result;
        }

        if (is_redirect) {
            if (already_crawled(crawled_data, redirect_location) != -1) {
                // Skip redirect if the URL was already crawled
                printf("Skipping redirect to already crawled URL: %s\n", redirect_location);
                fclose(file);
                return ERR_REDIRECT;
            }
            printf("Redirecting to: %s\n", redirect_location);
            int rebuild_result = rebuild_url(current_url, redirect_location, new_url);
            if (rebuild_result != SUCCESS) {
                fprintf(stderr, "Error rebuilding URL: %d\n", rebuild_result);
                fclose(file);
                return rebuild_result;
            }
            strncpy(current_url, new_url, BUFFER_SIZE);
            current_url[BUFFER_SIZE - 1] = '\0';
            redirect_count++;
        }
    } while (is_redirect && redirect_count < MAX_REDIRECTS);

    fclose(file);

    if (redirect_count >= MAX_REDIRECTS) {
        printf("Too many redirects\n");
        return ERR_REDIRECT;
    }

    printf("Response written to: %s\n", output_file);

    return SUCCESS;
}

void append_url(CrawledData *data, const char *url, int depth) {
    if (already_crawled(data, url) != -1) {
        printf("Skipping duplicate URL: %s\n", url);
        return;
    }

    if (data->crawled_count >= MAX_URLS) {
        fprintf(stderr, "Maximum number of URLs exceeded.\n");
        exit(ERR_BASE);
    }
    strncpy(data->crawled_urls[data->crawled_count], url, MAX_URL_LENGTH);
    data->status[data->crawled_count] = 1; // Mark as can_crawl
    data->depth[data->crawled_count] = depth;
    data->crawled_count++;
}

void rebuild_and_append_url(CrawledData *data, const char *href, int depth) {
    char full_url[BUFFER_SIZE];
    
    if (strstr(href, "http://") || strstr(href, "https://")) {
        strncpy(full_url, href, BUFFER_SIZE);
    } else {
        snprintf(full_url, BUFFER_SIZE, "%s%s", base_url, href);
    }

    append_url(data, full_url, depth);
}

void sanitize_filename(char *filename) {
    for (int i = 0; filename[i]; i++) {
        if (filename[i] == '/' || filename[i] == ':' || filename[i] == '?' || filename[i] == '&' || filename[i] == '=') {
            filename[i] = '_';  // Replace problematic characters with '_'
        }
    }
}

void child_process(CrawledData *crawled_data, const char *url, int child_id, int depth) {
    if (already_crawled(crawled_data, url) == 3) {
        printf("Skipping already crawled URL: %s\n", url);
        return;
    }

    const char *output_directory = "responses";
    struct stat st = {0};

    if (stat(output_directory, &st) == -1) {
        if (mkdir(output_directory, 0700) != 0) {
            perror("Failed to create output directory");
            exit(ERR_MKDIR);
        }
    }

    char sanitized_url[BUFFER_SIZE];
    strncpy(sanitized_url, url, BUFFER_SIZE);
    sanitize_filename(sanitized_url);

    char output_file[BUFFER_SIZE];
    snprintf(output_file, BUFFER_SIZE, "%s/%s.html", output_directory, sanitized_url);

    printf("Output file for URL %s is %s\n", url, output_file);

    int result = get_url_content(url, output_file);
    if (result == SUCCESS) {
        log_url_and_file(url, output_file);

        for (int i = 0; i < crawled_data->crawled_count; i++) {
            if (strcmp(crawled_data->crawled_urls[i], url) == 0) {
                crawled_data->status[i] = 3;
            }
        }

        if (depth < MAX_CRAWL_DEPTH) { 
            build_crawled_data(crawled_data, output_file, depth + 1);

            int new_child_id = crawled_data->crawled_count;
            while (new_child_id <= crawled_data->crawled_count) {
                if (already_crawled(crawled_data, crawled_data->crawled_urls[new_child_id - 1]) == 3) {
                    new_child_id++;
                    continue;
                }

                pid_t pid = fork();
                if (pid == -1) {
                    perror("Fork failed");
                    exit(ERR_FORK);
                } else if (pid == 0) {
                    child_process(crawled_data, crawled_data->crawled_urls[new_child_id - 1], new_child_id, depth + 1);
                    exit(SUCCESS);
                } else {
                    wait(NULL);
                    new_child_id++;
                }
            }
        }
    } else {
        fprintf(stderr, "Failed to fetch content for URL: %s\n", url);
    }
    exit(result);
}

int parse_url(const char *url, char *hostname, char *path) {
    if (url == NULL || hostname == NULL || path == NULL) {
        return ERR_PARAM;
    }

    const char *host_start = strstr(url, "//");
    if (host_start) {
        host_start += 2;
    } else {
        host_start = url;
    }

    const char *path_start = strchr(host_start, '/');
    if (path_start) {
        strncpy(hostname, host_start, path_start - host_start);
        hostname[path_start - host_start] = '\0';
        strcpy(path, path_start);
    } else {
        strcpy(hostname, host_start);
        strcpy(path, "/");
    }

    return SUCCESS;
}

int is_https(const char *url, char *hostname, char *path, char *request) {
    if (strncmp(url, "https://", 8) == 0) {
        snprintf(request, BUFFER_SIZE, "GET %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", path, hostname);
        return 1;  // HTTPS
    } else if (strncmp(url, "http://", 7) == 0) {
        snprintf(request, BUFFER_SIZE, "GET %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", path, hostname);
        return 0;  // HTTP
    } else {
        fprintf(stderr, "Invalid URL format, use http:// or https://\n");
        return ERR_URL;
    }
}

int print_status_code(const char *response) {
    const char *status_line = strstr(response, "HTTP/1.");
    if (status_line) {
        char status_code[4];
        strncpy(status_code, status_line + 9, 3);
        status_code[3] = '\0'; 
        return atoi(status_code);
    }
    
    fprintf(stderr, "Status code not found in response.\n");
    return ERR_STAT_CODE; 
}

int rebuild_url(const char *current_url, const char *redirect_location, char *new_url) {
    if (!current_url || !redirect_location || !new_url) {
        return ERR_PARAM;
    }

    if (strstr(redirect_location, "http://") || strstr(redirect_location, "https://")) {
        strncpy(new_url, redirect_location, BUFFER_SIZE - 1);
        new_url[BUFFER_SIZE - 1] = '\0';
    } else {
        const char *scheme_end = strstr(current_url, "://");
        if (!scheme_end) return ERR_URL;

        scheme_end += 3;
        const char *path_start = strchr(scheme_end, '/');
        size_t base_length = path_start ? (path_start - current_url) : strlen(current_url);

        if (base_length + strlen(redirect_location) >= BUFFER_SIZE) {
            return ERR_URL;
        }

        strncpy(new_url, current_url, base_length);
        new_url[base_length] = '\0';
        strncat(new_url, redirect_location, BUFFER_SIZE - base_length - 1);
    }

    return SUCCESS;
}

int fetch_url(const char *url, char *response, FILE *file, int *is_redirect, char *redirect_location) {
    if (!url || !response || !file || !is_redirect || !redirect_location) {
        return ERR_PARAM;
    }

    char hostname[BUFFER_SIZE];
    char path[BUFFER_SIZE];
    char request[BUFFER_SIZE];

    int status;
    int sockfd;
    int bytes_received;
    struct addrinfo hints, *res, *p;

    int use_ssl;
    SSL_CTX *ctx = NULL;
    SSL *ssl = NULL;

    if ((status = parse_url(url, hostname, path)) != SUCCESS) {
        return status;
    }

    use_ssl = is_https(url, hostname, path, request);
    if (use_ssl == ERR_URL) {
        return ERR_URL;
    }

    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    if ((status = getaddrinfo(hostname, use_ssl ? "443" : "80", &hints, &res)) != 0) {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(status));
        return ERR_GAI;
    }

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
        freeaddrinfo(res);
        return ERR_CONNECT;
    }

    freeaddrinfo(res);

    if (use_ssl) {
        SSL_library_init();
        SSL_load_error_strings();
        OpenSSL_add_all_algorithms();
        ctx = SSL_CTX_new(TLS_client_method());

        if (ctx == NULL) {
            ERR_print_errors_fp(stderr);
            close(sockfd);
            return ERR_SSL;
        }

        ssl = SSL_new(ctx);
        SSL_set_fd(ssl, sockfd);

        if (SSL_connect(ssl) <= 0) {
            ERR_print_errors_fp(stderr);
            SSL_free(ssl);
            SSL_CTX_free(ctx);
            close(sockfd);
            return ERR_SSL;
        }

        SSL_write(ssl, request, strlen(request));

        int header_done = 0;
        while ((bytes_received = SSL_read(ssl, response, BUFFER_SIZE - 1)) > 0) {
            response[bytes_received] = '\0';

            if (!header_done) {
                char *header_end = strstr(response, "\r\n\r\n");
                if (header_end) {
                    header_done = 1;

                    int status_code = print_status_code(response);
                    printf("Status Code : %d\n", status_code);

                    if (status_code == 200) {
                        strncpy(base_url, url, BUFFER_SIZE);
                    }

                    if (status_code == 301 || status_code == 302) {
                        *is_redirect = 1;
                        char *location = strstr(response, "Location:");
                        if (location) {
                            location += 9;
                            while (*location == ' ') location++;
                            char *end_location = strstr(location, "\r\n");
                            if (end_location) {
                                strncpy(redirect_location, location, end_location - location);
                                redirect_location[end_location - location] = '\0';
                                SSL_shutdown(ssl);
                                SSL_free(ssl);
                                SSL_CTX_free(ctx);
                                close(sockfd);
                                return SUCCESS;
                            }
                        }
                    }

                    char *body_start = header_end + 4;
                    fwrite(body_start, 1, bytes_received - (body_start - response), file);
                }
            } else {
                fwrite(response, 1, bytes_received, file);
            }
        }

        SSL_shutdown(ssl);
        SSL_free(ssl);
        SSL_CTX_free(ctx);
    } else {
        send(sockfd, request, strlen(request), 0);

        int header_done = 0;
        while ((bytes_received = recv(sockfd, response, BUFFER_SIZE - 1, 0)) > 0) {
            response[bytes_received] = '\0';

            if (!header_done) {
                char *header_end = strstr(response, "\r\n\r\n");
                if (header_end) {
                    header_done = 1;

                    int status_code = print_status_code(response);
                    printf("Status Code : %d\n", status_code);

                    if (status_code == 200) {
                        strncpy(base_url, url, BUFFER_SIZE);
                    }

                    if (status_code == 301 || status_code == 302) {
                        *is_redirect = 1;
                        char *location = strstr(response, "Location:");
                        if (location) {
                            location += 9;
                            while (*location == ' ') location++;
                            char *end_location = strstr(location, "\r\n");
                            if (end_location) {
                                strncpy(redirect_location, location, end_location - location);
                                redirect_location[end_location - location] = '\0';
                                close(sockfd);
                                return SUCCESS;
                            }
                        }
                    }

                    char *body_start = header_end + 4;
                    fwrite(body_start, 1, bytes_received - (body_start - response), file);
                }
            } else {
                fwrite(response, 1, bytes_received, file);
            }
        }
    }

    close(sockfd);
    return SUCCESS;
}

void build_crawled_data(CrawledData *data, const char *filename, int depth) {
    FILE *file = fopen(filename, "r");
    if (!file) {
        perror("Error opening file");
        return;
    }

    fseek(file, 0, SEEK_END);
    long file_size = ftell(file);
    fseek(file, 0, SEEK_SET);

    char *buffer = malloc(file_size + 1);
    if (!buffer) {
        perror("Error allocating memory");
        fclose(file);
        return;
    }

    fread(buffer, 1, file_size, file);
    buffer[file_size] = '\0';
    fclose(file);

    const char *pattern = "<a\\s+href=[\"']?([^\"' >]+)[\"' >]";

    regex_t regex;
    regmatch_t matches[2];
    if (regcomp(&regex, pattern, REG_EXTENDED) != 0) {
        perror("Error compiling regex");
        free(buffer);
        return;
    }

    char *cursor = buffer;
    while (regexec(&regex, cursor, 2, matches, 0) == 0) {
        int href_start = matches[1].rm_so;
        int href_end = matches[1].rm_eo;
        int href_length = href_end - href_start;

        char *href_value = malloc(href_length + 1);
        strncpy(href_value, cursor + href_start, href_length);
        href_value[href_length] = '\0';

        rebuild_and_append_url(data, href_value, depth);

        free(href_value);
        cursor += matches[0].rm_eo;
    }

    regfree(&regex);
    free(buffer);
}

int already_crawled(CrawledData *data, const char *url) {
    for (int i = 0; i < data->crawled_count; i++) {
        if (strcmp(data->crawled_urls[i], url) == 0) {
            return data->status[i];
        }
    }
    return -1;
}

int main(int argc, char *argv[]) {
    if (argc != 3) {
        fprintf(stderr, "Usage: %s <URL> <output_file_name(example.txt)>\n", argv[0]);
        return ERR_PARAM;
    }

    int shm_fd = shm_open("/my_shared_memory", O_CREAT | O_RDWR, 0666);
    if (shm_fd == -1) {
        perror("Failed to open shared memory");
        return ERR_SHM_OPEN;
    }

    if (ftruncate(shm_fd, sizeof(CrawledData)) == -1) {
        perror("Failed to resize shared memory");
        shm_unlink("/my_shared_memory");
        return ERR_SHM_UNLINK;
    }

    crawled_data = mmap(NULL, sizeof(CrawledData), PROT_READ | PROT_WRITE, MAP_SHARED, shm_fd, 0);
    if (crawled_data == MAP_FAILED) {
        perror("Failed to map shared memory");
        shm_unlink("/my_shared_memory");
        return ERR_SHM_MAP;
    }
    memset(crawled_data, 0, sizeof(CrawledData));

    int result = get_url_content(argv[1], argv[2]);
    if (result != SUCCESS) {
        return result;
    }

    build_crawled_data(crawled_data, argv[2], 1);

    int child_count = 0;
    int child_id = 1;
    while (child_id <= crawled_data->crawled_count) {
        if (already_crawled(crawled_data, crawled_data->crawled_urls[child_id - 1]) == 3) {
            child_id++;
            continue;
        }

        if (child_count >= MAX_CONCURRENT_CHILDREN) {
            printf("-------\nWaiting for child process\n-------\n");
            wait(NULL);
            child_count--;
        }

        pid_t pid = fork();
        if (pid == -1) {
            perror("Fork failed");
            return ERR_FORK;
        } else if (pid == 0) {
            child_process(crawled_data, crawled_data->crawled_urls[child_id - 1], child_id, 1);
        } else {
            child_count++;
            child_id++;
        }
    }

    while (child_count > 0) {
        printf("-------\nWaiting for child process\n-------\n");
        wait(NULL);
        child_count--;
    }

    printf("Final Extracted Links from array:\n");
    for (int i = 0; i < crawled_data->crawled_count; i++) {
        printf("%s\n", crawled_data->crawled_urls[i]);
    }

    munmap(crawled_data, sizeof(CrawledData));
    shm_unlink("/my_shared_memory");

    return SUCCESS;
}
