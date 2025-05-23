/* run commands
gcc -Wall -o sandbox cont.c -lutil -lcap
sudo ./sandbox -m alpine-rootfs -c /bin/sh*/
#define _GNU_SOURCE

#include <fcntl.h>
#include <errno.h>
#include <unistd.h>
#include <stdio.h>
#include <stdbool.h>
#include <time.h>
#include <getopt.h>
#include <sched.h>
#include <sys/utsname.h>
#include <signal.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <zconf.h>
#include <memory.h>
#include <sys/prctl.h>
#include <sys/capability.h>
#include <linux/capability.h>
#include <sys/mount.h>
#include <sys/syscall.h>
#include <sys/stat.h>
#define STACK_SIZE (1024 * 1024)
struct proc_info {
    int argc;        // Number of args for child process.
    char **argv;     // Args for child process.
    char *hostname;  // Hostname of child process.
    char *mount_dir; // Filesystem where containers should be mounted.
};
bool choose_hostname(char *hostname, size_t i);
int drop_capabilities() {
    fprintf(stderr, "=> setting up process capabilities...");
    int caps_list[] = {
            CAP_SYS_ADMIN
    };
    size_t num_caps = sizeof(caps_list) / sizeof(*caps_list);
    fprintf(stderr, "bounding...");
    for (size_t i = 0; i < num_caps; i++) {
        if (prctl(PR_CAPBSET_DROP, caps_list[i], 0, 0, 0)) {
            fprintf(stderr, "prctl failed: %m\n");
            return 1;
        }
    }
    fprintf(stderr, "inheritable...");
    cap_t caps = NULL;
    if (!(caps = cap_get_proc())
        || cap_set_flag(caps, CAP_INHERITABLE, num_caps, caps_list, CAP_CLEAR)
        || cap_set_proc(caps)) {
        fprintf(stderr, "failed: %m\n");
        if (caps) cap_free(caps);
        return 1;
    }
    cap_free(caps);
    fprintf(stderr, "done.\n");
    return 0;
}
int pivot_root(const char *new_root, const char *put_old)
{
    return syscall(SYS_pivot_root, new_root, put_old);
}
int prepare_procfs()
{
    if (rmdir("/proc")) {
        fprintf(stderr, "rmdir /proc failed! %m\n");
        return -1;
    }
    if (mkdir("/proc", 0555)) {
        fprintf(stderr, "Failed to mkdir /proc! \n");
        return -1;
    }
    if (mount("proc", "/proc", "proc", 0, "")) {
        fprintf(stderr, "Failed to mount proc! \n");
        return -1;
    }
    return 0;
}
int setmountns(struct proc_info *info)
{
    fprintf(stderr, "=> mounting MNT namespace to %s\n", info->mount_dir);
    fprintf(stderr, "=> remounting everything with MS_PRIVATE...");
    if (mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL)) {
        fprintf(stderr, "failed! %m\n");
        return -1;
    }
    fprintf(stderr, "remounted.\n");
    fprintf(stderr, "=> making a temp directory and a bind mount there...");
    char mount_dir[] = "/tmp/tmp.XXXXXX";
    if (!mkdtemp(mount_dir)) {
        fprintf(stderr, "failed making a directory!\n");
        return -1;
    }
    if (mount(info->mount_dir, mount_dir, NULL, MS_BIND | MS_PRIVATE, NULL)) {
        fprintf(stderr, "bind mount failed!\n");
        return -1;
    }
    char inner_mount_dir[] = "/tmp/tmp.XXXXXX/oldroot.XXXXXX";
    memcpy(inner_mount_dir, mount_dir, sizeof(mount_dir) - 1);
    if (!mkdtemp(inner_mount_dir)) {
        fprintf(stderr, "failed making the inner directory!\n");
        return -1;
    }
    fprintf(stderr, "done.\n");
    fprintf(stderr, "=> pivoting root...");
    if (pivot_root(mount_dir, inner_mount_dir)) {
        fprintf(stderr, "failed!\n");
        return -1;
    }
    fprintf(stderr, "done.\n");
    char *old_root_dir = basename(inner_mount_dir);
    char old_root[sizeof(inner_mount_dir) + 1] = { "/" };
    strcpy(&old_root[1], old_root_dir);
    if(prepare_procfs()) {
        fprintf(stderr, "Preparing procfs failed! %m\n");
        return -1;
    }
    
    fprintf(stderr, "=> mounting cgroup2 at /sys/fs/cgroup...\n");
    if (mkdir("/sys/fs/cgroup", 0755) && errno != EEXIST) {
        fprintf(stderr, "mkdir /sys/fs/cgroup failed: %m\n");
        return -1;
    }
    if (mount("none", "/sys/fs/cgroup", "cgroup2", 0, "") != 0) {
        fprintf(stderr, "mount cgroup2 failed: %m\n");
        return -1;
    }
    fprintf(stderr, "cgroup2 mounted successfully.\n");
    
    fprintf(stderr, "=> unmounting %s...", old_root);
    if (chdir("/")) {
        fprintf(stderr, "chdir failed! %m\n");
        return -1;
    }
    if (umount2(old_root, MNT_DETACH)) {
        fprintf(stderr, "umount failed! %m\n");
        return -1;
    }
    if (rmdir(old_root)) {
        fprintf(stderr, "rmdir failed! %m\n");
        return -1;
    }
    fprintf(stderr, "done.\n");

    return 0;
}
int enable_controllers() {
    FILE *fp = fopen("/sys/fs/cgroup/cgroup.subtree_control", "w");
    if (!fp) {
        perror("enable_controllers: fopen");
        return -1;
    }
    fprintf(fp, "+cpu +memory +pids\n");
    fclose(fp);
    return 0;
}
int setup_cgroup(pid_t pid) {
    const char *cg_path = "/sys/fs/cgroup/mycontainer";
    if (mkdir(cg_path, 0755) && errno != EEXIST) {
        perror("mkdir cgroup");
        fprintf(stderr, "=> [cgroup] Failed to create cgroup directory.\n");
        return -1;
    }

    // Set max processes (pids controller)
    FILE *fp = fopen("/sys/fs/cgroup/mycontainer/pids.max", "w");
    if (!fp) { 
        perror("pids.max"); 
        fprintf(stderr, "=> [cgroup] Failed to open pids.max\n");
        return -1; 
    }
    fprintf(fp, "10");
    fclose(fp);

    // Set memory limit to 100MB (memory controller)
    fp = fopen("/sys/fs/cgroup/mycontainer/memory.max", "w");
    if (!fp) { 
        perror("memory.max"); 
        fprintf(stderr, "=> [cgroup] Failed to open memory.max\n");
        return -1; 
    }
    fprintf(fp, "%ld", 100L * 1024 * 1024);  // 100MB
    fclose(fp);

    // Set CPU limit to 50% of one core (cpu controller)
    fp = fopen("/sys/fs/cgroup/mycontainer/cpu.max", "w");
    if (!fp) { 
        perror("cpu.max"); 
        fprintf(stderr, "=> [cgroup] Failed to open cpu.max\n");
        return -1; 
    }
    fprintf(fp, "%s", "50000 100000");  // quota=50000µs per 100000µs period (i.e., 50%)
    fclose(fp);

    // Add this process to the cgroup
    char pid_str[20];
    snprintf(pid_str, sizeof(pid_str), "%d", pid);
    fp = fopen("/sys/fs/cgroup/mycontainer/cgroup.procs", "w");
    if (!fp) { 
        perror("cgroup.procs"); 
        fprintf(stderr, "=> [cgroup] Failed to add pid to cgroup.procs\n");
        return -1; 
    }
    fprintf(fp, "%s", pid_str);
    fclose(fp);

    fprintf(stdout, "=> [cgroup] Successfully set cgroup limits for pid %d\n", pid);
    return 0;
}

static int childFunc(void *arg)
{
    struct proc_info *info = arg;

    if (sethostname(info->hostname, strlen(info->hostname)) ||
        setmountns(info))
        return -1;

    drop_capabilities();

    struct utsname uts;
    if (uname(&uts) == -1)
        return -1;

    fprintf(stdout, "Child process started. Hostname: %s\n", uts.nodename);

    if (execve(info->argv[0], info->argv, NULL)) {
        fprintf(stderr, "execve failed! %m.\n");
        return -1;
    }

    sleep(10); // fallback sleep if execve fails
    return 0;
}
int create_child_process(int flags, struct proc_info *config)
{
    enable_controllers();  // ensure cgroup controllers are enabled

    int err = 0;
    char *stack;
    char *stackTop;
    pid_t pid;

    if (!(stack = malloc(STACK_SIZE))) {
        fprintf(stderr, "=> malloc failed, out of memory?\n");
        return -1;
    }

    stackTop = stack + STACK_SIZE;
    pid = clone(childFunc, stackTop, flags | SIGCHLD, config);

    if (pid == -1) {
        fprintf(stderr, "=> child clone failed.\n");
        free(stack);
        return -1;
    }

    fprintf(stdout, "=> child process created with PID %d\n", pid);

    if (setup_cgroup(pid)) {
        fprintf(stderr, "=> Failed to apply cgroup limits!\n");
        kill(pid, SIGKILL);
        free(stack);
        return -1;
    }

    int child_status = 0;
    waitpid(pid, &child_status, 0);
    err |= WEXITSTATUS(child_status);

    // Cleanup cgroup
    rmdir("/sys/fs/cgroup/mycontainer");

    fprintf(stdout, "=> child exited with %d\n", WEXITSTATUS(child_status));
    free(stack);
    return err;
}
int main(int argc, char **argv) {
    struct proc_info config = {0};
    int err = 0;
    int option = 0;
    int lastopt = 0;
    while ((option = getopt(argc, argv, "c:m:"))) {
        switch (option) {
            case 'c':
                config.argc = argc - lastopt - 1;
                config.argv = &argv[argc - 1];
                goto finish_config;
            case 'm':
                config.mount_dir = optarg;
                break;
            default:
                goto usage;
        }
    }
finish_config:
    if (!config.argc) goto usage;
    if (!config.mount_dir) goto usage;
    fprintf(stdout, "=> choosing hostname for container..\n");
    char hostname[10] = {0};
    if (choose_hostname(hostname, sizeof(hostname)))
        goto err;
    config.hostname = hostname;
    fprintf(stdout, "=> Hostname: %s\n", config.hostname);
    if(create_child_process(CLONE_NEWNS | CLONE_NEWPID | CLONE_NEWUTS, &config) == -1) {
        fprintf(stderr, "=> create child process failed! %m\n");
        goto err;
    }
    goto cleanup;
usage:
    fprintf(stderr, "Usage: %s -m <mount-dir> -c /bin/sh ~\n", argv[0]);
err:
    err = 1;
cleanup:
    fprintf(stdout, "Done.\n");
    return err;
}
bool choose_hostname(char *buff, size_t len) {
    struct timespec now = {0};
    clock_gettime(CLOCK_MONOTONIC, &now);
    snprintf(buff, len, "%s-%05lx", "cnt", now.tv_sec);
    return 0;
}
