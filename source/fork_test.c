#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include <string.h>

#define MAX_CHILD 3
#define MAX_URLS 10
#define MAX_URL_LENGTH 1024

// Define the struct for tracking crawled data
typedef struct {
    char crawled_urls[MAX_URLS][MAX_URL_LENGTH];  // Array for storing URLs
    int status[MAX_URLS];                         // Status of each URL (0 = not crawled, 1 = crawling, 2 = crawled)
} crawled_data;

// Function for each child process to loop and crawl data
void child_process(crawled_data *data, int id) {
    while (1) {
        int task_index = -1;

        // Look for a task to process (where status == 0)
        for (int i = 0; i < MAX_URLS; i++) {
            if (data->status[i] == 0) {  // Found a task that hasn't been crawled
                task_index = i;
                data->status[i] = 1;  // Mark it as being crawled
                break;
            }
        }

        if (task_index == -1) {
            // If no task was found, all tasks are processed, so exit
            printf("Child %d: All tasks are processed. Exiting.\n", id);
            break;
        }

        // Simulate crawling a URL
        printf("Child %d started crawling URL: %s\n", id, data->crawled_urls[task_index]);
        sleep(1);  // Simulate crawling delay
        printf("Child %d finished crawling URL: %s\n", id, data->crawled_urls[task_index]);

        // Mark the task as crawled
        data->status[task_index] = 2;
    }
    _exit(0);  // Child exits when done
}

int main() {
    // Create shared memory for the crawled_data structure
    crawled_data *data = mmap(NULL, sizeof(crawled_data), PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    if (data == MAP_FAILED) {
        perror("mmap failed");
        return 1;
    }

    // Initialize the array of URLs and status
    const char *urls[MAX_URLS] = {
        "https://example.com",
        "https://example.org",
        "https://example.net",
        "https://example.com/1",
        "https://example.org/2",
        "https://example.net/3",
        "https://example.com/4",
        "https://example.org/5",
        "https://example.net/6",
        "https://example.com/7"
    };

    for (int i = 0; i < MAX_URLS; i++) {
        strncpy(data->crawled_urls[i], urls[i], MAX_URL_LENGTH - 1);  // Copy the URL
        data->status[i] = 0;  // Mark all as "not crawled"
    }

    // Create exactly 3 child processes that will loop over tasks
    pid_t pids[MAX_CHILD];
    for (int i = 0; i < MAX_CHILD; i++) {
        pids[i] = fork();

        if (pids[i] < 0) {
            perror("Fork failed");
            return 1;
        } else if (pids[i] == 0) {
            // This is the child process
            child_process(data, i + 1);  // Child process function
        }
    }

    // Wait for all child processes to finish
    for (int i = 0; i < MAX_CHILD; i++) {
        waitpid(pids[i], NULL, 0);
    }

    // Print the status of each element after all processes are done
    printf("Crawling results:\n");
    for (int i = 0; i < MAX_URLS; i++) {
        printf("URL: %s, Status: %d\n", data->crawled_urls[i], data->status[i]);
    }

    printf("All crawling processes completed.\n");

    // Unmap shared memory
    munmap(data, sizeof(crawled_data));

    return 0;
}
