#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <time.h>

#include <pwd.h>
#include <fcntl.h>

#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <linux/fs.h>

#define VICTIM_USERNAME "newt"
#define MAX_BUFFER_SIZE 4000

const int SIGNALS[] = {SIGSEGV, SIGILL, SIGBUS};
const int SIGNALS_LEN = 2;

int bof(uint8_t* data);

void set_cookie();
void clear_cookie();

int parent_main(pid_t child_pid);
int child_main(int argc, char** argv);

void sig_handler(int signum);


int main(int argc, char** argv, char** envp) {
    set_cookie();

    for (int i=0; i < SIGNALS_LEN; ++i){
        signal(SIGNALS[i], sig_handler);
    }

    pid_t pid = fork();
    if (pid < 0) {
        printf("Error initializing prog\n");
        exit(1);
    }

    if (pid > 0) {
        parent_main(pid);
    }
    else {
        return child_main(argc, argv);
    }

}

int bof(uint8_t* data) {
#ifdef BUFFER_SIZE
    uint8_t vuln_buffer[BUFFER_SIZE];
    strcpy(vuln_buffer, data);
#endif
    return 0;
}

void set_cookie() {
    int cookie_file_fd = open(".assn5_cookie", O_RDONLY | O_CREAT, S_IRWXU);

    int curr_flags;
    ioctl(cookie_file_fd, FS_IOC_GETFLAGS, &curr_flags);

    curr_flags |= FS_IMMUTABLE_FL;
    ioctl(cookie_file_fd, FS_IOC_SETFLAGS, &curr_flags);

    close(cookie_file_fd);
}

void clear_cookie() {
    int cookie_file_fd = open(".assn5_cookie", O_RDONLY);

    int curr_flags;
    ioctl(cookie_file_fd, FS_IOC_GETFLAGS, &curr_flags);

    curr_flags ^= FS_IMMUTABLE_FL;
    ioctl(cookie_file_fd, FS_IOC_SETFLAGS, &curr_flags);

    close(cookie_file_fd);
    remove(".assn5_cookie");
}

int parent_main(pid_t child_pid) {
    int ret;
    waitpid(child_pid, &ret, 0);
    clear_cookie();

    int extracted_signal = ((ret >> 8) & 0xFF);
    // printf("child ret: %d\n", ret);
    // printf("extracted: %d\n", extracted_signal);

    for (int i=0; i < SIGNALS_LEN; ++i){
        if (extracted_signal == SIGNALS[i]) {
            signal(SIGNALS[i], SIG_DFL);
            raise(SIGNALS[i]);
        }
    }

    return ret;
}

int child_main(int argc, char** argv) {
#ifndef BUFFER_SIZE
        printf("Something went wrong. No defined buffer size.\n");
        exit(1);
#endif

    if (argc < 2) {
        printf("Thank you for playing.\n");
        return 0;
    }


    struct passwd* victim_info = getpwnam(VICTIM_USERNAME);
    uid_t victim_uid = victim_info->pw_uid;
    setuid(victim_uid);

    uint8_t input[MAX_BUFFER_SIZE + 0x100];

    FILE* input_file = fopen(argv[1], "r");
    if (!input_file) {
        printf("Thank you for playing?\n");
        return 1;
    }


    if (!fread(input, 1, MAX_BUFFER_SIZE + 0x100, input_file)) {
        printf("Thank you for playing,\n");
        return 0;
    }


    bof(input);
    printf("Thank you for playing!\n");

    return 0;

}

void sig_handler(int signum) {
    exit(signum);
}
