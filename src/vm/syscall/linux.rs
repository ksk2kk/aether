use crate::arch::x86_64::vmx::GuestRegisters;
use crate::vm::hypercall::utils::{copy_guest_gpa_bytes, copy_bytes_to_guest_gpa};
use crate::vm::fs::{get_vfs, OpenFlags, FileMode, SeekFrom, Stat};
use crate::memory::ept::EptManager;
use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use alloc::string::String;
use alloc::boxed::Box;
use alloc::sync::Arc;
use spin::Mutex;
use super::SyscallHandler;

const SYS_READ: u64 = 0;
const SYS_WRITE: u64 = 1;
const SYS_OPEN: u64 = 2;
const SYS_CLOSE: u64 = 3;
const SYS_FSTAT: u64 = 5;
const SYS_MMAP: u64 = 9;
const SYS_MPROTECT: u64 = 10;
const SYS_MUNMAP: u64 = 11;
const SYS_BRK: u64 = 12;
const SYS_RT_SIGACTION: u64 = 13;
const SYS_RT_SIGPROCMASK: u64 = 14;
const SYS_IOCTL: u64 = 16;
const SYS_ACCESS: u64 = 21;
const SYS_SCHED_YIELD: u64 = 24;
const SYS_GETPID: u64 = 39;
const SYS_CLONE: u64 = 56;
const SYS_FORK: u64 = 57;
const SYS_VFORK: u64 = 58;
const SYS_EXECVE: u64 = 59;
const SYS_EXIT: u64 = 60;
const SYS_WAIT4: u64 = 61;
const SYS_KILL: u64 = 62;
const SYS_UNAME: u64 = 63;
const SYS_FCNTL: u64 = 72;
const SYS_TRUNCATE: u64 = 76;
const SYS_FTRUNCATE: u64 = 77;
const SYS_GETCWD: u64 = 79;
const SYS_CHDIR: u64 = 80;
const SYS_FCHDIR: u64 = 81;
const SYS_RENAME: u64 = 82;
const SYS_MKDIR: u64 = 83;
const SYS_RMDIR: u64 = 84;
const SYS_CREAT: u64 = 85;
const SYS_LINK: u64 = 86;
const SYS_UNLINK: u64 = 87;
const SYS_SYMLINK: u64 = 88;
const SYS_READLINK: u64 = 89;
const SYS_CHMOD: u64 = 90;
const SYS_FCHMOD: u64 = 91;
const SYS_CHOWN: u64 = 92;
const SYS_FCHOWN: u64 = 93;
const SYS_LCHOWN: u64 = 94;
const SYS_UMASK: u64 = 95;
const SYS_GETTIMEOFDAY: u64 = 96;
const SYS_TIME: u64 = 201;
const SYS_GETRLIMIT: u64 = 97;
const SYS_GETRUSAGE: u64 = 98;
const SYS_SYSINFO: u64 = 99;
const SYS_TIMES: u64 = 100;
const SYS_GETUID: u64 = 102;
const SYS_GETGID: u64 = 104;
const SYS_SETUID: u64 = 105;
const SYS_SETGID: u64 = 106;
const SYS_GETEUID: u64 = 107;
const SYS_GETEGID: u64 = 108;
const SYS_SETPGID: u64 = 109;
const SYS_GETPPID: u64 = 110;
const SYS_GETPGRP: u64 = 111;
const SYS_SETSID: u64 = 112;
const SYS_GETPGID: u64 = 121;
const SYS_ARCH_PRCTL: u64 = 158;
const SYS_EXIT_GROUP: u64 = 231;
const SYS_SET_TID_ADDRESS: u64 = 218;
const SYS_FUTEX: u64 = 202;
const SYS_SET_ROBUST_LIST: u64 = 273;
const SYS_GET_ROBUST_LIST: u64 = 274;
const SYS_PRCTL: u64 = 157;
const SYS_GETRANDOM: u64 = 318;
const SYS_CLOCK_GETTIME: u64 = 228;
const SYS_NANOSLEEP: u64 = 35;
const SYS_POLL: u64 = 7;
const SYS_SELECT: u64 = 23;
const SYS_EPOLL_CREATE: u64 = 212;
const SYS_EPOLL_CTL: u64 = 233;
const SYS_EPOLL_WAIT: u64 = 232;
const SYS_EVENTFD: u64 = 284;
const SYS_EVENTFD2: u64 = 290;
const SYS_TIMERFD_CREATE: u64 = 283;
const SYS_SIGNALFD: u64 = 282;
const SYS_INOTIFY_INIT: u64 = 253;
const SYS_INOTIFY_INIT1: u64 = 294;
const SYS_INOTIFY_ADD_WATCH: u64 = 254;
const SYS_INOTIFY_RM_WATCH: u64 = 255;
const SYS_DUP: u64 = 32;
const SYS_DUP2: u64 = 33;
const SYS_PIPE: u64 = 22;
const SYS_PIPE2: u64 = 293;
const SYS_SOCKET: u64 = 41;
const SYS_CONNECT: u64 = 42;
const SYS_ACCEPT: u64 = 43;
const SYS_SENDTO: u64 = 44;
const SYS_RECVFROM: u64 = 45;
const SYS_SHUTDOWN: u64 = 48;
const SYS_BIND: u64 = 49;
const SYS_LISTEN: u64 = 50;
const SYS_GETSOCKOPT: u64 = 55;
const SYS_SETSOCKOPT: u64 = 54;
const SYS_GETSOCKNAME: u64 = 51;
const SYS_GETPEERNAME: u64 = 52;
const SYS_STATX: u64 = 332;
const SYS_MEMFD_CREATE: u64 = 319;
const SYS_READLINKAT: u64 = 267;
const SYS_NEWFSTATAT: u64 = 262;
const SYS_UNLINKAT: u64 = 263;
const SYS_RENAMEAT: u64 = 264;
const SYS_LINKAT: u64 = 265;
const SYS_SYMLINKAT: u64 = 266;
const SYS_FCHMODAT: u64 = 268;
const SYS_FACCESSAT: u64 = 269;
const SYS_OPENAT: u64 = 257;
const SYS_MKDIRAT: u64 = 258;
const SYS_MKNODAT: u64 = 259;
const SYS_FCHOWNAT: u64 = 260;
const SYS_FUTIMESAT: u64 = 261;
const SYS_GETDENTS64: u64 = 217;
const SYS_LSEEK: u64 = 8;
const SYS_READV: u64 = 19;
const SYS_WRITEV: u64 = 20;
const SYS_PREAD64: u64 = 17;
const SYS_PWRITE64: u64 = 18;
const SYS_SENDFILE: u64 = 40;
const SYS_PSELECT6: u64 = 270;
const SYS_PPOLL: u64 = 271;
const SYS_UNSHARE: u64 = 272;
const SYS_SPLICE: u64 = 275;
const SYS_TEE: u64 = 276;
const SYS_VMSPLICE: u64 = 278;
const SYS_SYNC_FILE_RANGE: u64 = 277;
const SYS_FALLOCATE: u64 = 285;
const SYS_ACCEPT4: u64 = 288;
const SYS_RECVMMSG: u64 = 299;
const SYS_SENDMMSG: u64 = 307;
const SYS_MLOCK: u64 = 149;
const SYS_MUNLOCK: u64 = 150;
const SYS_MLOCKALL: u64 = 151;
const SYS_MUNLOCKALL: u64 = 152;
const SYS_MINCORE: u64 = 219;
const SYS_MADVISE: u64 = 28;
const SYS_MREMAP: u64 = 25;
const SYS_FSYNC: u64 = 74;
const SYS_FDATASYNC: u64 = 75;
const SYS_MSYNC: u64 = 26;
const SYS_FLOCK: u64 = 73;
const SYS_FADVISE64: u64 = 221;
const SYS_STAT: u64 = 4;
const SYS_LSTAT: u64 = 6;
const SYS_STATFS: u64 = 137;
const SYS_FSTATFS: u64 = 138;
const SYS_GETDENTS: u64 = 78;
const SYS_GETSID: u64 = 124;
const SYS_SETREUID: u64 = 113;
const SYS_SETREGID: u64 = 114;
const SYS_SETRESUID: u64 = 117;
const SYS_GETRESUID: u64 = 118;
const SYS_SETRESGID: u64 = 119;
const SYS_GETRESGID: u64 = 120;
const SYS_SETFSUID: u64 = 122;
const SYS_SETFSGID: u64 = 123;
const SYS_GETGROUPS: u64 = 115;
const SYS_SETGROUPS: u64 = 116;
const SYS_SETPRIORITY: u64 = 141;
const SYS_GETPRIORITY: u64 = 140;
const SYS_SCHED_SETSCHEDULER: u64 = 144;
const SYS_SCHED_GETSCHEDULER: u64 = 145;
const SYS_SCHED_SETPARAM: u64 = 142;
const SYS_SCHED_GETPARAM: u64 = 143;
const SYS_SCHED_GET_PRIORITY_MAX: u64 = 146;
const SYS_SCHED_GET_PRIORITY_MIN: u64 = 147;
const SYS_SCHED_RR_GET_INTERVAL: u64 = 148;
const SYS_RT_SIGPENDING: u64 = 127;
const SYS_RT_SIGTIMEDWAIT: u64 = 128;
const SYS_RT_SIGQUEUEINFO: u64 = 129;
const SYS_RT_SIGSUSPEND: u64 = 130;
const SYS_SIGALTSTACK: u64 = 131;
const SYS_TIMER_CREATE: u64 = 222;
const SYS_TIMER_SETTIME: u64 = 223;
const SYS_TIMER_GETTIME: u64 = 224;
const SYS_TIMER_GETOVERRUN: u64 = 225;
const SYS_TIMER_DELETE: u64 = 226;
const SYS_CLOCK_SETTIME: u64 = 227;
const SYS_CLOCK_GETRES: u64 = 229;
const SYS_CLOCK_NANOSLEEP: u64 = 230;
const SYS_SYSLOG: u64 = 103;
const SYS_UTIME: u64 = 132;
const SYS_UTIMES: u64 = 235;
const SYS_UTIMENSAT: u64 = 280;
const SYS_ADJTIMEX: u64 = 159;
const SYS_SETRLIMIT: u64 = 160;
const SYS_CHROOT: u64 = 161;
const SYS_SYNC: u64 = 162;
const SYS_ACCT: u64 = 163;
const SYS_SETTIMEOFDAY: u64 = 164;
const SYS_MOUNT: u64 = 165;
const SYS_UMOUNT2: u64 = 166;
const SYS_SWAPON: u64 = 167;
const SYS_SWAPOFF: u64 = 168;
const SYS_REBOOT: u64 = 169;
const SYS_SETHOSTNAME: u64 = 170;
const SYS_SETDOMAINNAME: u64 = 171;
const SYS_IOPL: u64 = 172;
const SYS_IOPERM: u64 = 173;
const SYS_CREATE_MODULE: u64 = 174;
const SYS_INIT_MODULE: u64 = 175;
const SYS_DELETE_MODULE: u64 = 176;
const SYS_GET_KERNEL_SYMS: u64 = 177;
const SYS_QUERY_MODULE: u64 = 178;
const SYS_QUOTACTL: u64 = 179;
const SYS_NFSSERVCTL: u64 = 180;
const SYS_AFS_SYSCALL: u64 = 183;
const SYS_SECURITY: u64 = 185;
const SYS_GETTID: u64 = 186;
const SYS_READAHEAD: u64 = 187;
const SYS_SETXATTR: u64 = 188;
const SYS_LSETXATTR: u64 = 189;
const SYS_FSETXATTR: u64 = 190;
const SYS_GETXATTR: u64 = 191;
const SYS_LGETXATTR: u64 = 192;
const SYS_FGETXATTR: u64 = 193;
const SYS_LISTXATTR: u64 = 194;
const SYS_LLISTXATTR: u64 = 195;
const SYS_FLISTXATTR: u64 = 196;
const SYS_REMOVEXATTR: u64 = 197;
const SYS_LREMOVEXATTR: u64 = 198;
const SYS_FREMOVEXATTR: u64 = 199;
const SYS_SCHED_SET_AFFINITY: u64 = 203;
const SYS_SCHED_GET_AFFINITY: u64 = 204;
const SYS_IO_SETUP: u64 = 206;
const SYS_IO_DESTROY: u64 = 207;
const SYS_IO_GETEVENTS: u64 = 208;
const SYS_IO_SUBMIT: u64 = 209;
const SYS_IO_CANCEL: u64 = 210;
const SYS_GET_THREAD_AREA: u64 = 211;
const SYS_RESTART_SYSCALL: u64 = 219;
const SYS_SEMTIMEDOP: u64 = 220;
const SYS_TGKILL: u64 = 234;
const SYS_VSERVER: u64 = 236;
const SYS_MBIND: u64 = 237;
const SYS_SET_MEMPOLICY: u64 = 238;
const SYS_GET_MEMPOLICY: u64 = 239;
const SYS_MQ_OPEN: u64 = 240;
const SYS_MQ_UNLINK: u64 = 241;
const SYS_MQ_TIMEDSEND: u64 = 242;
const SYS_MQ_TIMEDRECEIVE: u64 = 243;
const SYS_MQ_NOTIFY: u64 = 244;
const SYS_MQ_GETSETATTR: u64 = 245;
const SYS_KEXEC_LOAD: u64 = 246;
const SYS_WAITID: u64 = 247;
const SYS_ADD_KEY: u64 = 248;
const SYS_REQUEST_KEY: u64 = 249;
const SYS_KEYCTL: u64 = 250;
const SYS_IOPRIO_SET: u64 = 251;
const SYS_IOPRIO_GET: u64 = 252;
const SYS_MIGRATE_PAGES: u64 = 256;
const SYS_EPOLL_PWAIT: u64 = 281;
const SYS_SIGNALFD4: u64 = 289;
const SYS_TIMERFD_SETTIME: u64 = 286;
const SYS_TIMERFD_GETTIME: u64 = 287;
const SYS_EPOLL_CREATE1: u64 = 291;
const SYS_DUP3: u64 = 292;
const SYS_PREADV: u64 = 295;
const SYS_PWRITEV: u64 = 296;
const SYS_RT_TGSIGQUEUEINFO: u64 = 297;
const SYS_PERF_EVENT_OPEN: u64 = 298;
const SYS_FANOTIFY_INIT: u64 = 300;
const SYS_FANOTIFY_MARK: u64 = 301;
const SYS_PRLIMIT64: u64 = 302;
const SYS_NAME_TO_HANDLE_AT: u64 = 303;
const SYS_OPEN_BY_HANDLE_AT: u64 = 304;
const SYS_CLOCK_ADJTIME: u64 = 305;
const SYS_SYNCFS: u64 = 306;
const SYS_SETNS: u64 = 308;
const SYS_GETCPU: u64 = 309;
const SYS_PROCESS_VM_READV: u64 = 310;
const SYS_PROCESS_VM_WRITEV: u64 = 311;
const SYS_KCMP: u64 = 312;
const SYS_FINIT_MODULE: u64 = 313;
const SYS_SCHED_SETATTR: u64 = 314;
const SYS_SCHED_GETATTR: u64 = 315;
const SYS_RENAMEAT2: u64 = 316;
const SYS_SECCOMP: u64 = 317;
const SYS_PKEY_MPROTECT: u64 = 329;
const SYS_PKEY_ALLOC: u64 = 330;
const SYS_PKEY_FREE: u64 = 331;
const SYS_USERFAULTFD: u64 = 323;
const SYS_MEMBARRIER: u64 = 324;
const SYS_MLOCK2: u64 = 325;
const SYS_COPY_FILE_RANGE: u64 = 326;
const SYS_PREADV2: u64 = 327;
const SYS_PWRITEV2: u64 = 328;
const SYS_KEXEC_FILE_LOAD: u64 = 320;
const SYS_BPF: u64 = 321;
const SYS_EXECVEAT: u64 = 322;
const SYS_PERSONALITY: u64 = 135;
const SYS_VHANGUP: u64 = 153;
const SYS_MODIFY_LDT: u64 = 154;
const SYS_PIVOT_ROOT: u64 = 155;
const SYS__SYSCTL: u64 = 156;
const SYS_PTRACE: u64 = 101;
const SYS_SEMGET: u64 = 64;
const SYS_SEMOP: u64 = 65;
const SYS_SEMCTL: u64 = 66;
const SYS_SHMDT: u64 = 67;
const SYS_SHMGET: u64 = 29;
const SYS_SHMAT: u64 = 30;
const SYS_SHMCTL: u64 = 31;
const SYS_MSGGET: u64 = 68;
const SYS_MSGSND: u64 = 69;
const SYS_MSGRCV: u64 = 70;
const SYS_MSGCTL: u64 = 71;
const SYS_MKNOD: u64 = 133;
const SYS_USELIB: u64 = 134;
const SYS_USTAT: u64 = 136;
const SYS_LOOP_CTL: u64 = 333;
const SYS_LOOP_CONFIGURE: u64 = 334;

pub const ENOSYS: i64 = -38;
pub const EINVAL: i64 = -22;
pub const ENOMEM: i64 = -12;
pub const EBADF: i64 = -9;
pub const EFAULT: i64 = -14;
pub const ERANGE: i64 = -34;
pub const ENOENT: i64 = -2;
pub const EISDIR: i64 = -21;
pub const EAGAIN: i64 = -11;
pub const ENFILE: i64 = -23;
pub const EMFILE: i64 = -24;
pub const ESPIPE: i64 = -29;
pub const EEXIST: i64 = -17;
pub const ENOTDIR: i64 = -20;
pub const ENXIO: i64 = -6;
pub const EPERM: i64 = -1;
pub const EACCES: i64 = -13;
pub const ETIMEDOUT: i64 = -110;
pub const EINTR: i64 = -4;

const SEEK_SET: i32 = 0;
const SEEK_CUR: i32 = 1;
const SEEK_END: i32 = 2;

const PROT_NONE: u64 = 0x0;
const PROT_READ: u64 = 0x1;
const PROT_WRITE: u64 = 0x2;
const PROT_EXEC: u64 = 0x4;

const MAP_SHARED: u64 = 0x01;
const MAP_PRIVATE: u64 = 0x02;
const MAP_SHARED_VALIDATE: u64 = 0x03;
const MAP_TYPE: u64 = 0x0f;
const MAP_FIXED: u64 = 0x10;
const MAP_ANONYMOUS: u64 = 0x20;
const MAP_32BIT: u64 = 0x40;
const MAP_GROWSDOWN: u64 = 0x0100;
const MAP_DENYWRITE: u64 = 0x0800;
const MAP_EXECUTABLE: u64 = 0x1000;
const MAP_LOCKED: u64 = 0x2000;
const MAP_NORESERVE: u64 = 0x4000;
const MAP_POPULATE: u64 = 0x8000;
const MAP_NONBLOCK: u64 = 0x10000;
const MAP_STACK: u64 = 0x20000;
const MAP_HUGETLB: u64 = 0x40000;
const MAP_SYNC: u64 = 0x80000;
const MAP_FIXED_NOREPLACE: u64 = 0x100000;

const MREMAP_MAYMOVE: u64 = 1;
const MREMAP_FIXED: u64 = 2;
const MREMAP_DONTUNMAP: u64 = 4;

const CLONE_VM: u64 = 0x00000100;
const CLONE_FS: u64 = 0x00000200;
const CLONE_FILES: u64 = 0x00000400;
const CLONE_SIGHAND: u64 = 0x00000800;
const CLONE_PIDFD: u64 = 0x00001000;
const CLONE_PTRACE: u64 = 0x00002000;
const CLONE_VFORK: u64 = 0x00004000;
const CLONE_PARENT: u64 = 0x00008000;
const CLONE_THREAD: u64 = 0x00010000;
const CLONE_NEWNS: u64 = 0x00020000;
const CLONE_SYSVSEM: u64 = 0x00040000;
const CLONE_SETTLS: u64 = 0x00080000;
const CLONE_PARENT_SETTID: u64 = 0x00100000;
const CLONE_CHILD_CLEARTID: u64 = 0x00200000;
const CLONE_DETACHED: u64 = 0x00400000;
const CLONE_UNTRACED: u64 = 0x00800000;
const CLONE_CHILD_SETTID: u64 = 0x01000000;
const CLONE_NEWCGROUP: u64 = 0x02000000;
const CLONE_NEWUTS: u64 = 0x04000000;
const CLONE_NEWIPC: u64 = 0x08000000;
const CLONE_NEWUSER: u64 = 0x10000000;
const CLONE_NEWPID: u64 = 0x20000000;
const CLONE_NEWNET: u64 = 0x40000000;
const CLONE_IO: u64 = 0x80000000;

const CLOCK_REALTIME: i32 = 0;
const CLOCK_MONOTONIC: i32 = 1;
const CLOCK_PROCESS_CPUTIME_ID: i32 = 2;
const CLOCK_THREAD_CPUTIME_ID: i32 = 3;
const CLOCK_MONOTONIC_RAW: i32 = 4;
const CLOCK_REALTIME_COARSE: i32 = 5;
const CLOCK_MONOTONIC_COARSE: i32 = 6;
const CLOCK_BOOTTIME: i32 = 7;
const CLOCK_REALTIME_ALARM: i32 = 8;
const CLOCK_BOOTTIME_ALARM: i32 = 9;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProcessState {
    Running,
    Runnable,
    Sleeping,
    Stopped,
    Zombie,
}

#[derive(Debug, Clone)]
pub struct Process {
    pub pid: i32,
    pub ppid: i32,
    pub state: ProcessState,
    pub exit_code: i32,
    pub uid: u32,
    pub gid: u32,
    pub euid: u32,
    pub egid: u32,
    pub thread_group: i32,
    pub children: Vec<i32>,
    pub waiters: Vec<i32>,
}

impl Process {
    pub fn new(pid: i32, ppid: i32) -> Self {
        Self {
            pid,
            ppid,
            state: ProcessState::Running,
            exit_code: 0,
            uid: 0,
            gid: 0,
            euid: 0,
            egid: 0,
            thread_group: pid,
            children: Vec::new(),
            waiters: Vec::new(),
        }
    }
}

pub struct ProcessManager {
    processes: BTreeMap<i32, Process>,
    next_pid: i32,
    current_pid: i32,
}

impl ProcessManager {
    pub fn new() -> Self {
        let mut processes = BTreeMap::new();
        let init = Process::new(1, 0);
        processes.insert(1, init);
        
        Self {
            processes,
            next_pid: 2,
            current_pid: 1,
        }
    }

    pub fn current(&self) -> Option<&Process> {
        self.processes.get(&self.current_pid)
    }

    pub fn current_mut(&mut self) -> Option<&mut Process> {
        self.processes.get_mut(&self.current_pid)
    }

    pub fn get(&self, pid: i32) -> Option<&Process> {
        self.processes.get(&pid)
    }

    pub fn get_mut(&mut self, pid: i32) -> Option<&mut Process> {
        self.processes.get_mut(&pid)
    }

    pub fn create_process(&mut self, parent_pid: i32) -> Option<i32> {
        let pid = self.next_pid;
        self.next_pid += 1;
        
        let child = Process::new(pid, parent_pid);
        self.processes.insert(pid, child);
        
        if let Some(parent) = self.processes.get_mut(&parent_pid) {
            parent.children.push(pid);
        }
        
        Some(pid)
    }

    pub fn exit_process(&mut self, pid: i32, exit_code: i32) {
        if let Some(proc) = self.processes.get_mut(&pid) {
            proc.state = ProcessState::Zombie;
            proc.exit_code = exit_code;
        }
    }

    pub fn remove_zombie(&mut self, pid: i32) -> Option<i32> {
        if let Some(proc) = self.processes.get(&pid) {
            if proc.state == ProcessState::Zombie {
                let exit_code = proc.exit_code;
                self.processes.remove(&pid);
                return Some(exit_code);
            }
        }
        None
    }

    pub fn has_zombie_child(&self, ppid: i32) -> Option<i32> {
        for (pid, proc) in &self.processes {
            if proc.ppid == ppid && proc.state == ProcessState::Zombie {
                return Some(*pid);
            }
        }
        None
    }
}

static PROCESS_MANAGER: Mutex<Option<ProcessManager>> = Mutex::new(None);

pub fn init_process_manager() {
    *PROCESS_MANAGER.lock() = Some(ProcessManager::new());
    crate::log_info!("进程管理器初始化完成");
}

pub struct Pipe {
    pub buffer: Vec<u8>,
    pub read_end: bool,
    pub write_end: bool,
}

impl Pipe {
    pub fn new() -> Self {
        Self {
            buffer: Vec::with_capacity(4096),
            read_end: true,
            write_end: true,
        }
    }

    pub fn read(&mut self, buf: &mut [u8]) -> Result<usize, i64> {
        if self.buffer.is_empty() {
            return Ok(0);
        }
        let len = core::cmp::min(buf.len(), self.buffer.len());
        buf[..len].copy_from_slice(&self.buffer[..len]);
        self.buffer.drain(..len);
        Ok(len)
    }

    pub fn write(&mut self, buf: &[u8]) -> Result<usize, i64> {
        if self.buffer.len() + buf.len() > 65536 {
            return Err(-EAGAIN);
        }
        self.buffer.extend_from_slice(buf);
        Ok(buf.len())
    }
}

static mut PIPES: Option<BTreeMap<i32, Arc<Mutex<Pipe>>>> = None;

pub fn init_pipes() {
    unsafe {
        PIPES = Some(BTreeMap::new());
    }
}

pub struct LinuxSyscallHandler;

static mut BRK_CURRENT: u64 = 0x4000_0000;
static mut MMAP_NEXT: u64 = 0x7000_0000;

impl SyscallHandler for LinuxSyscallHandler {
    fn handle_syscall(&self, regs: &mut GuestRegisters) -> bool {
        let syscall_nr = regs.rax;
        let result = match syscall_nr {
            SYS_READ => sys_read(regs),
            SYS_WRITE => sys_write(regs),
            SYS_OPEN => sys_open(regs),
            SYS_CLOSE => sys_close(regs),
            SYS_BRK => sys_brk(regs),
            SYS_MMAP => sys_mmap(regs),
            SYS_MUNMAP => sys_munmap(regs),
            SYS_MPROTECT => sys_mprotect(regs),
            SYS_GETPID => sys_getpid(regs),
            SYS_GETPPID => sys_getppid(regs),
            SYS_GETUID => sys_getuid(regs),
            SYS_GETEUID => sys_geteuid(regs),
            SYS_GETGID => sys_getgid(regs),
            SYS_GETEGID => sys_getegid(regs),
            SYS_UNAME => sys_uname(regs),
            SYS_ARCH_PRCTL => sys_arch_prctl(regs),
            SYS_EXIT | SYS_EXIT_GROUP => sys_exit(regs),
            SYS_SCHED_YIELD => sys_sched_yield(regs),
            SYS_FSTAT => sys_fstat(regs),
            SYS_LSEEK => sys_lseek(regs),
            SYS_IOCTL => sys_ioctl(regs),
            SYS_ACCESS => sys_access(regs),
            SYS_GETCWD => sys_getcwd(regs),
            SYS_CHDIR | SYS_FCHDIR => sys_chdir(regs),
            SYS_FCNTL => sys_fcntl(regs),
            SYS_GETDENTS64 | SYS_GETDENTS => sys_getdents64(regs),
            SYS_DUP => sys_dup(regs),
            SYS_DUP2 => sys_dup2(regs),
            SYS_PIPE | SYS_PIPE2 => sys_pipe(regs),
            SYS_SOCKET | SYS_CONNECT | SYS_ACCEPT | SYS_SENDTO | SYS_RECVFROM |
            SYS_SHUTDOWN | SYS_BIND | SYS_LISTEN => ENOSYS as u64,
            SYS_GETSOCKOPT | SYS_SETSOCKOPT | SYS_GETSOCKNAME | SYS_GETPEERNAME => 0,
            SYS_POLL | SYS_SELECT | SYS_PSELECT6 | SYS_PPOLL => 0,
            SYS_EPOLL_CREATE | SYS_EPOLL_CREATE1 => 4,
            SYS_EPOLL_CTL | SYS_EPOLL_WAIT | SYS_EPOLL_PWAIT => 0,
            SYS_EVENTFD | SYS_EVENTFD2 => 5,
            SYS_TIMERFD_CREATE => 6,
            SYS_SIGNALFD | SYS_SIGNALFD4 => 7,
            SYS_INOTIFY_INIT | SYS_INOTIFY_INIT1 => 8,
            SYS_INOTIFY_ADD_WATCH => 1,
            SYS_INOTIFY_RM_WATCH => 0,
            SYS_CLONE => sys_clone(regs),
            SYS_FORK => sys_fork(regs),
            SYS_VFORK => sys_vfork(regs),
            SYS_EXECVE => sys_execve(regs),
            SYS_WAIT4 => sys_wait4(regs),
            SYS_KILL | SYS_TGKILL => 0,
            SYS_RT_SIGACTION | SYS_RT_SIGPROCMASK => 0,
            SYS_PRCTL => sys_prctl(regs),
            SYS_FUTEX => 0,
            SYS_SET_TID_ADDRESS => 1,
            SYS_SET_ROBUST_LIST | SYS_GET_ROBUST_LIST => 0,
            SYS_GETRANDOM => sys_getrandom(regs),
            SYS_MEMFD_CREATE => 10,
            SYS_STATX | SYS_NEWFSTATAT | SYS_STAT | SYS_LSTAT | SYS_FSTAT => 0,
            SYS_CLOCK_GETTIME => sys_clock_gettime(regs),
            SYS_CLOCK_GETRES => sys_clock_getres(regs),
            SYS_NANOSLEEP | SYS_CLOCK_NANOSLEEP => sys_nanosleep(regs),
            SYS_GETTIMEOFDAY => sys_gettimeofday(regs),
            SYS_TIME | SYS_TIMES | SYS_SYSINFO => 0,
            SYS_GETRLIMIT | SYS_SETRLIMIT | SYS_GETRUSAGE => 0,
            SYS_UMASK => 0o022,
            SYS_CHMOD | SYS_FCHMOD | SYS_FCHMODAT => 0,
            SYS_CHOWN | SYS_FCHOWN | SYS_LCHOWN | SYS_FCHOWNAT => 0,
            SYS_MKDIR | SYS_MKDIRAT => 0,
            SYS_RMDIR => 0,
            SYS_CREAT | SYS_MKNOD | SYS_MKNODAT => ENOSYS as u64,
            SYS_LINK | SYS_LINKAT => 0,
            SYS_UNLINK | SYS_UNLINKAT => 0,
            SYS_SYMLINK | SYS_SYMLINKAT => 0,
            SYS_READLINK | SYS_READLINKAT => 0,
            SYS_RENAME | SYS_RENAMEAT | SYS_RENAMEAT2 => 0,
            SYS_TRUNCATE | SYS_FTRUNCATE => 0,
            SYS_FSYNC | SYS_FDATASYNC | SYS_MSYNC => 0,
            SYS_FLOCK | SYS_MADVISE => 0,
            SYS_MREMAP => sys_mremap(regs),
            SYS_MLOCK | SYS_MUNLOCK | SYS_MLOCKALL | SYS_MUNLOCKALL | SYS_MINCORE => 0,
            SYS_READV | SYS_WRITEV | SYS_PREADV | SYS_PWRITEV | SYS_PREADV2 | SYS_PWRITEV2 => 0,
            SYS_PREAD64 | SYS_PWRITE64 => 0,
            SYS_SENDFILE | SYS_COPY_FILE_RANGE => 0,
            SYS_SYNC | SYS_SYNCFS => 0,
            SYS_FALLOCATE | SYS_FADVISE64 => 0,
            SYS_STATFS | SYS_FSTATFS | SYS_USTAT => 0,
            SYS_MOUNT | SYS_UMOUNT2 => 0,
            SYS_PIVOT_ROOT | SYS_CHROOT => 0,
            SYS_SETHOSTNAME | SYS_SETDOMAINNAME => 0,
            SYS_SYSLOG => 0,
            SYS_UTIME | SYS_UTIMES | SYS_UTIMENSAT | SYS_FUTIMESAT => 0,
            SYS_ADJTIMEX | SYS_SETTIMEOFDAY => 0,
            SYS_REBOOT => 0,
            SYS_IOPL | SYS_IOPERM | SYS_MODIFY_LDT => 0,
            SYS_CREATE_MODULE | SYS_INIT_MODULE | SYS_DELETE_MODULE | SYS_FINIT_MODULE => 0,
            SYS_GET_KERNEL_SYMS | SYS_QUERY_MODULE => 0,
            SYS_QUOTACTL | SYS_NFSSERVCTL | SYS_AFS_SYSCALL | SYS_SECURITY => 0,
            SYS_GETTID => 1,
            SYS_READAHEAD => 0,
            SYS_SETXATTR | SYS_LSETXATTR | SYS_FSETXATTR => 0,
            SYS_GETXATTR | SYS_LGETXATTR | SYS_FGETXATTR => 0,
            SYS_LISTXATTR | SYS_LLISTXATTR | SYS_FLISTXATTR => 0,
            SYS_REMOVEXATTR | SYS_LREMOVEXATTR | SYS_FREMOVEXATTR => 0,
            SYS_SCHED_SET_AFFINITY | SYS_SCHED_GET_AFFINITY => 0,
            SYS_IO_SETUP | SYS_IO_DESTROY | SYS_IO_GETEVENTS | SYS_IO_SUBMIT | SYS_IO_CANCEL => 0,
            SYS_GET_THREAD_AREA => 0,
            SYS_RESTART_SYSCALL => 0,
            SYS_SEMTIMEDOP | SYS_SEMOP | SYS_SEMCTL | SYS_SEMGET => 0,
            SYS_SHMGET | SYS_SHMAT | SYS_SHMDT | SYS_SHMCTL => 0,
            SYS_MSGGET | SYS_MSGSND | SYS_MSGRCV | SYS_MSGCTL => 0,
            SYS_TIMER_CREATE | SYS_TIMER_SETTIME | SYS_TIMER_GETTIME | SYS_TIMER_GETOVERRUN | SYS_TIMER_DELETE => 0,
            SYS_TIMERFD_SETTIME | SYS_TIMERFD_GETTIME => 0,
            SYS_CLOCK_SETTIME => 0,
            SYS_MBIND | SYS_SET_MEMPOLICY | SYS_GET_MEMPOLICY => 0,
            SYS_MQ_OPEN | SYS_MQ_UNLINK | SYS_MQ_TIMEDSEND | SYS_MQ_TIMEDRECEIVE |
            SYS_MQ_NOTIFY | SYS_MQ_GETSETATTR => 0,
            SYS_KEXEC_LOAD | SYS_KEXEC_FILE_LOAD => 0,
            SYS_WAITID => 0,
            SYS_ADD_KEY | SYS_REQUEST_KEY | SYS_KEYCTL => 0,
            SYS_IOPRIO_SET | SYS_IOPRIO_GET => 0,
            SYS_MIGRATE_PAGES => 0,
            SYS_RT_SIGPENDING | SYS_RT_SIGTIMEDWAIT | SYS_RT_SIGQUEUEINFO | SYS_RT_SIGSUSPEND => 0,
            SYS_SIGALTSTACK => 0,
            SYS_ACCEPT4 | SYS_RECVMMSG | SYS_SENDMMSG => 0,
            SYS_FANOTIFY_INIT | SYS_FANOTIFY_MARK => 0,
            SYS_PRLIMIT64 => 0,
            SYS_NAME_TO_HANDLE_AT | SYS_OPEN_BY_HANDLE_AT => 0,
            SYS_CLOCK_ADJTIME => 0,
            SYS_SETNS => 0,
            SYS_GETCPU => 0,
            SYS_PROCESS_VM_READV | SYS_PROCESS_VM_WRITEV => 0,
            SYS_KCMP => 0,
            SYS_SCHED_SETATTR | SYS_SCHED_GETATTR => 0,
            SYS_SECCOMP => 0,
            SYS_PKEY_MPROTECT | SYS_PKEY_ALLOC | SYS_PKEY_FREE => 0,
            SYS_USERFAULTFD => 0,
            SYS_MEMBARRIER => 0,
            SYS_MLOCK2 => 0,
            SYS_UNSHARE | SYS_SPLICE | SYS_TEE | SYS_VMSPLICE | SYS_SYNC_FILE_RANGE => 0,
            SYS_PERSONALITY | SYS_VHANGUP | SYS_USELIB | SYS_PIVOT_ROOT | SYS__SYSCTL => 0,
            SYS_PTRACE => 0,
            SYS_SETPGID | SYS_GETPGRP | SYS_SETSID | SYS_GETSID | SYS_GETPGID => 0,
            SYS_SETREUID | SYS_SETREGID | SYS_SETRESUID | SYS_GETRESUID |
            SYS_SETRESGID | SYS_GETRESGID | SYS_SETUID | SYS_SETGID |
            SYS_SETFSUID | SYS_SETFSGID | SYS_GETGROUPS | SYS_SETGROUPS => 0,
            SYS_SETPRIORITY | SYS_GETPRIORITY => 0,
            SYS_SCHED_SETSCHEDULER | SYS_SCHED_GETSCHEDULER | SYS_SCHED_SETPARAM |
            SYS_SCHED_GETPARAM | SYS_SCHED_GET_PRIORITY_MAX | SYS_SCHED_GET_PRIORITY_MIN |
            SYS_SCHED_RR_GET_INTERVAL => 0,
            SYS_ACCT | SYS_SWAPON | SYS_SWAPOFF => 0,
            SYS_FACCESSAT => 0,
            SYS_OPENAT => ENOSYS as u64,
            SYS_BPF => 0,
            SYS_EXECVEAT => ENOSYS as u64,
            SYS_LOOP_CTL | SYS_LOOP_CONFIGURE => -ENOSYS as u64,
            _ => {
                crate::log_debug!("未实现的系统调用: nr={}, rdi={:#x}, rsi={:#x}, rdx={:#x}",
                    syscall_nr, regs.rdi, regs.rsi, regs.rdx);
                ENOSYS as u64
            }
        };

        regs.rax = result;
        true
    }
}

fn get_current_ept() -> Option<crate::memory::ept::EptManager> {
    let mut mgr = crate::enclave::get_manager();
    let manager = mgr.as_mut()?;
    let cur = manager.current_id()?;
    let enclave = manager.get_enclave_mut(cur)?;
    Some(enclave.ept.clone())
}

fn read_string_from_guest(gpa: u64, max_len: usize) -> Option<alloc::string::String> {
    let mut mgr = crate::enclave::get_manager();
    let manager = mgr.as_mut()?;
    let cur = manager.current_id()?;
    let enclave = manager.get_enclave_mut(cur)?;
    
    let mut buf = [0u8; 256];
    let mut result = alloc::string::String::new();
    let mut offset = 0u64;
    
    loop {
        let n = copy_guest_gpa_bytes(&enclave.ept, gpa + offset, &mut buf);
        if n == 0 {
            break;
        }
        
        for i in 0..n {
            if buf[i] == 0 {
                return Some(result);
            }
            if buf[i].is_ascii_graphic() || buf[i] == b'/' || buf[i] == b'.' || buf[i] == b' ' || buf[i] == b'-' || buf[i] == b'_' {
                result.push(buf[i] as char);
            } else {
                return None;
            }
        }
        
        offset += n as u64;
        if result.len() >= max_len {
            break;
        }
    }
    
    Some(result)
}

fn sys_read(regs: &mut GuestRegisters) -> u64 {
    let fd = regs.rdi as i32;
    let buf_gpa = regs.rsi;
    let count = regs.rdx as usize;

    if fd < 0 {
        return (-EBADF) as u64;
    }
    if count == 0 {
        return 0;
    }

    let vfs = unsafe { get_vfs().as_mut() };
    if vfs.is_none() {
        return (-ENOENT) as u64;
    }
    let vfs = vfs.unwrap();

    let mut mgr = crate::enclave::get_manager();
    let manager = match mgr.as_mut() {
        Some(m) => m,
        None => return (-EFAULT) as u64,
    };
    let cur = match manager.current_id() {
        Some(id) => id,
        None => return (-EFAULT) as u64,
    };
    let enclave = match manager.get_enclave_mut(cur) {
        Some(e) => e,
        None => return (-EFAULT) as u64,
    };

    let mut chunk_buf = [0u8; 4096];
    let mut total_read = 0usize;
    let mut remaining = count;

    while remaining > 0 {
        let chunk = core::cmp::min(remaining, 4096);
        match vfs.read(fd, &mut chunk_buf[..chunk], &enclave.ept) {
            Ok(0) => break,
            Ok(n) => {
                copy_bytes_to_guest_gpa(&enclave.ept, buf_gpa + total_read as u64, &chunk_buf[..n]);
                total_read += n;
                remaining -= n;
                if n < chunk {
                    break;
                }
            }
            Err(e) => return (-e) as u64,
        }
    }

    total_read as u64
}

fn sys_write(regs: &mut GuestRegisters) -> u64 {
    let fd = regs.rdi as i32;
    let buf_gpa = regs.rsi;
    let count = regs.rdx as usize;

    if fd < 0 {
        return (-EBADF) as u64;
    }
    if count == 0 {
        return 0;
    }

    let vfs = unsafe { get_vfs().as_mut() };
    if vfs.is_none() {
        return (-ENOENT) as u64;
    }
    let vfs = vfs.unwrap();

    let mut mgr = crate::enclave::get_manager();
    let manager = match mgr.as_mut() {
        Some(m) => m,
        None => return (-EFAULT) as u64,
    };
    let cur = match manager.current_id() {
        Some(id) => id,
        None => return (-EFAULT) as u64,
    };
    let enclave = match manager.get_enclave_mut(cur) {
        Some(e) => e,
        None => return (-EFAULT) as u64,
    };

    let mut chunk_buf = [0u8; 4096];
    let mut total_written = 0usize;
    let mut remaining = count;

    while remaining > 0 {
        let chunk = core::cmp::min(remaining, 4096);
        let n = copy_guest_gpa_bytes(&enclave.ept, buf_gpa + total_written as u64, &mut chunk_buf[..chunk]);
        if n == 0 {
            break;
        }
        
        match vfs.write(fd, &chunk_buf[..n], &enclave.ept) {
            Ok(written) => {
                total_written += written;
                remaining -= written;
                if written < n {
                    break;
                }
            }
            Err(e) => return (-e) as u64,
        }
    }

    total_written as u64
}

fn sys_open(regs: &mut GuestRegisters) -> u64 {
    let path_gpa = regs.rdi;
    let flags_raw = regs.rsi as i32;
    let mode_raw = regs.rdx as u32;

    let path = match read_string_from_guest(path_gpa, 256) {
        Some(p) => p,
        None => return (-ENOENT) as u64,
    };

    let flags = match OpenFlags::from_bits(flags_raw & 0x00FF_FFFF) {
        Some(f) => f,
        None => return (-EINVAL) as u64,
    };

    let mode = FileMode::from_bits_truncate(mode_raw & 0o777);

    let vfs = unsafe { get_vfs().as_mut() };
    if vfs.is_none() {
        return (-ENOENT) as u64;
    }
    let vfs = vfs.unwrap();

    match vfs.open(&path, flags, mode) {
        Ok(fd) => fd as u64,
        Err(e) => (-e) as u64,
    }
}

fn sys_close(regs: &mut GuestRegisters) -> u64 {
    let fd = regs.rdi as i32;

    let vfs = unsafe { get_vfs().as_mut() };
    if vfs.is_none() {
        return (-EBADF) as u64;
    }
    let vfs = vfs.unwrap();

    match vfs.close(fd) {
        Ok(()) => 0,
        Err(e) => (-e) as u64,
    }
}

fn sys_brk(regs: &mut GuestRegisters) -> u64 {
    let addr = regs.rdi;
    unsafe {
        if addr == 0 {
            return BRK_CURRENT;
        }
        if addr >= 0x4000_0000 && addr < 0x8000_0000 {
            if addr > BRK_CURRENT {
                let mut mgr = crate::enclave::get_manager();
                if let Some(manager) = mgr.as_mut() {
                    if let Some(cur) = manager.current_id() {
                        if let Some(enclave) = manager.get_enclave_mut(cur) {
                            let start_gpa = (BRK_CURRENT + 0xFFF) & !0xFFF;
                            let end_gpa = (addr + 0xFFF) & !0xFFF;
                            let mut gpa = start_gpa;
                            while gpa < end_gpa {
                                if let Some(frame) = crate::memory::allocate_frame() {
                                    let hpa = frame.start_address();
                                    let flags = crate::memory::ept::EptFlags::READ 
                                        | crate::memory::ept::EptFlags::WRITE
                                        | crate::memory::ept::EptFlags::EXECUTE
                                        | crate::memory::ept::EptFlags::MEMORY_TYPE_WB;
                                    enclave.ept.map(x86_64::PhysAddr::new(gpa), hpa, flags);
                                }
                                gpa += 4096;
                            }
                        }
                    }
                }
            }
            BRK_CURRENT = addr;
            return addr;
        }
    }
    (-ENOMEM) as u64
}

fn allocate_guest_pages(gpa: u64, len: u64, prot: u64) -> bool {
    let aligned_len = (len + 0xFFF) & !0xFFF;
    let start_gpa = gpa & !0xFFF;
    
    let mut mgr = crate::enclave::get_manager();
    if let Some(manager) = mgr.as_mut() {
        if let Some(cur) = manager.current_id() {
            if let Some(enclave) = manager.get_enclave_mut(cur) {
                let mut flags = crate::memory::ept::EptFlags::MEMORY_TYPE_WB;
                if (prot & PROT_READ) != 0 {
                    flags |= crate::memory::ept::EptFlags::READ;
                }
                if (prot & PROT_WRITE) != 0 {
                    flags |= crate::memory::ept::EptFlags::WRITE;
                }
                if (prot & PROT_EXEC) != 0 {
                    flags |= crate::memory::ept::EptFlags::EXECUTE;
                }
                
                let mut current_gpa = start_gpa;
                let end_gpa = start_gpa + aligned_len;
                while current_gpa < end_gpa {
                    if let Some(frame) = crate::memory::allocate_frame() {
                        let hpa = frame.start_address();
                        enclave.ept.map(x86_64::PhysAddr::new(current_gpa), hpa, flags);
                    } else {
                        return false;
                    }
                    current_gpa += 4096;
                }
                return true;
            }
        }
    }
    false
}

fn sys_mmap(regs: &mut GuestRegisters) -> u64 {
    let addr = regs.rdi;
    let len = regs.rsi;
    let prot = regs.rdx;
    let flags = regs.r10;
    let fd = regs.r8 as i32;
    let offset = regs.r9;

    if len == 0 {
        return (-EINVAL) as u64;
    }

    let aligned_len = (len + 0xFFF) & !0xFFF;
    let is_anonymous = (flags & MAP_ANONYMOUS) != 0;
    let is_fixed = (flags & MAP_FIXED) != 0;
    let is_private = (flags & MAP_PRIVATE) != 0;
    let is_shared = (flags & MAP_SHARED) != 0;

    if !is_anonymous && !is_private && !is_shared {
        return (-EINVAL) as u64;
    }

    let result_addr: u64;

    unsafe {
        if is_fixed && addr != 0 {
            if addr < 0x1000_0000 || addr >= 0x8000_0000 {
                return (-EINVAL) as u64;
            }
            result_addr = addr & !0xFFF;
        } else {
            result_addr = MMAP_NEXT;
            MMAP_NEXT += aligned_len;
        }

        if is_anonymous {
            if allocate_guest_pages(result_addr, aligned_len, prot) {
                let mut mgr = crate::enclave::get_manager();
                if let Some(manager) = mgr.as_mut() {
                    if let Some(cur) = manager.current_id() {
                        if let Some(enclave) = manager.get_enclave_mut(cur) {
                            let mut current_gpa = result_addr;
                            let end_gpa = result_addr + aligned_len;
                            while current_gpa < end_gpa {
                                if let Some(hpa) = enclave.ept.translate_gpa(x86_64::PhysAddr::new(current_gpa)) {
                                    let virt = crate::memory::phys_to_virt(hpa);
                                    unsafe {
                                        let ptr = virt.as_u64() as *mut u8;
                                        for i in 0..4096 {
                                            ptr.add(i).write_volatile(0);
                                        }
                                    }
                                }
                                current_gpa += 4096;
                            }
                        }
                    }
                }
                result_addr
            } else {
                (-ENOMEM) as u64
            }
        } else {
            if allocate_guest_pages(result_addr, aligned_len, prot) {
                result_addr
            } else {
                (-ENOMEM) as u64
            }
        }
    }
}

fn sys_munmap(regs: &mut GuestRegisters) -> u64 {
    let addr = regs.rdi;
    let len = regs.rsi;

    if len == 0 {
        return (-EINVAL) as u64;
    }
    if (addr & 0xFFF) != 0 {
        return (-EINVAL) as u64;
    }

    let aligned_len = (len + 0xFFF) & !0xFFF;
    let start_gpa = addr & !0xFFF;
    
    let mut mgr = crate::enclave::get_manager();
    if let Some(manager) = mgr.as_mut() {
        if let Some(cur) = manager.current_id() {
            if let Some(enclave) = manager.get_enclave_mut(cur) {
                let mut current_gpa = start_gpa;
                let end_gpa = start_gpa + aligned_len;
                while current_gpa < end_gpa {
                    let _ = enclave.ept.unmap(x86_64::PhysAddr::new(current_gpa));
                    current_gpa += 4096;
                }
                return 0;
            }
        }
    }
    
    (-EINVAL) as u64
}

fn sys_mprotect(regs: &mut GuestRegisters) -> u64 {
    let addr = regs.rdi;
    let len = regs.rsi;
    let prot = regs.rdx;

    if len == 0 {
        return 0;
    }
    if (addr & 0xFFF) != 0 {
        return (-EINVAL) as u64;
    }

    let aligned_len = (len + 0xFFF) & !0xFFF;
    let start_gpa = addr & !0xFFF;
    
    let mut mgr = crate::enclave::get_manager();
    if let Some(manager) = mgr.as_mut() {
        if let Some(cur) = manager.current_id() {
            if let Some(enclave) = manager.get_enclave_mut(cur) {
                let mut flags = crate::memory::ept::EptFlags::MEMORY_TYPE_WB;
                if (prot & PROT_READ) != 0 {
                    flags |= crate::memory::ept::EptFlags::READ;
                }
                if (prot & PROT_WRITE) != 0 {
                    flags |= crate::memory::ept::EptFlags::WRITE;
                }
                if (prot & PROT_EXEC) != 0 {
                    flags |= crate::memory::ept::EptFlags::EXECUTE;
                }
                
                let mut current_gpa = start_gpa;
                let end_gpa = start_gpa + aligned_len;
                while current_gpa < end_gpa {
                    if let Some(hpa) = enclave.ept.translate_gpa(x86_64::PhysAddr::new(current_gpa)) {
                        enclave.ept.map(x86_64::PhysAddr::new(current_gpa), hpa, flags);
                    }
                    current_gpa += 4096;
                }
                return 0;
            }
        }
    }
    
    (-ENOMEM) as u64
}

fn sys_getpid(regs: &mut GuestRegisters) -> u64 {
    1
}

fn sys_getppid(regs: &mut GuestRegisters) -> u64 {
    0
}

fn sys_getuid(regs: &mut GuestRegisters) -> u64 {
    0
}

fn sys_geteuid(regs: &mut GuestRegisters) -> u64 {
    0
}

fn sys_getgid(regs: &mut GuestRegisters) -> u64 {
    0
}

fn sys_getegid(regs: &mut GuestRegisters) -> u64 {
    0
}

fn sys_uname(regs: &mut GuestRegisters) -> u64 {
    let buf_gpa = regs.rdi;
    
    let mut mgr = crate::enclave::get_manager();
    let manager = match mgr.as_mut() {
        Some(m) => m,
        None => return EFAULT as u64,
    };
    let cur = match manager.current_id() {
        Some(id) => id,
        None => return EFAULT as u64,
    };
    let enclave = match manager.get_enclave_mut(cur) {
        Some(e) => e,
        None => return EFAULT as u64,
    };

    let mut utsname = [0u8; 390];
    let sysname = b"Linux\0";
    let nodename = b"aether\0";
    let release = b"6.1.0-aether\0";
    let version = b"#1 SMP\0";
    let machine = b"x86_64\0";
    let domainname = b"(none)\0";

    fn copy_to_buf(buf: &mut [u8], offset: usize, src: &[u8]) {
        let len = core::cmp::min(src.len(), buf.len() - offset);
        buf[offset..offset + len].copy_from_slice(&src[..len]);
    }

    copy_to_buf(&mut utsname, 0, sysname);
    copy_to_buf(&mut utsname, 65, nodename);
    copy_to_buf(&mut utsname, 130, release);
    copy_to_buf(&mut utsname, 195, version);
    copy_to_buf(&mut utsname, 260, machine);
    copy_to_buf(&mut utsname, 325, domainname);

    copy_bytes_to_guest_gpa(&enclave.ept, buf_gpa, &utsname);
    0
}

const ARCH_SET_GS: i32 = 0x1001;
const ARCH_SET_FS: i32 = 0x1002;
const ARCH_GET_FS: i32 = 0x1003;
const ARCH_GET_GS: i32 = 0x1004;

fn sys_arch_prctl(regs: &mut GuestRegisters) -> u64 {
    let option = regs.rdi as i32;
    let addr = regs.rsi;

    match option {
        ARCH_SET_FS => {
            unsafe { crate::vm::exit::GUEST_MSR_STATE.fs_base = addr };
            0
        }
        ARCH_SET_GS => {
            unsafe { crate::vm::exit::GUEST_MSR_STATE.gs_base = addr };
            0
        }
        ARCH_GET_FS => {
            let mut mgr = crate::enclave::get_manager();
            if let Some(manager) = mgr.as_mut() {
                if let Some(cur) = manager.current_id() {
                    if let Some(enclave) = manager.get_enclave_mut(cur) {
                        let val = unsafe { crate::vm::exit::GUEST_MSR_STATE.fs_base };
                        let val_bytes = val.to_ne_bytes();
                        copy_bytes_to_guest_gpa(&enclave.ept, addr, &val_bytes);
                        return 0;
                    }
                }
            }
            EFAULT as u64
        }
        ARCH_GET_GS => {
            let mut mgr = crate::enclave::get_manager();
            if let Some(manager) = mgr.as_mut() {
                if let Some(cur) = manager.current_id() {
                    if let Some(enclave) = manager.get_enclave_mut(cur) {
                        let val = unsafe { crate::vm::exit::GUEST_MSR_STATE.gs_base };
                        let val_bytes = val.to_ne_bytes();
                        copy_bytes_to_guest_gpa(&enclave.ept, addr, &val_bytes);
                        return 0;
                    }
                }
            }
            EFAULT as u64
        }
        _ => EINVAL as u64,
    }
}

fn sys_exit(regs: &mut GuestRegisters) -> u64 {
    let exit_code = regs.rdi as i32;
    crate::log_info!("隔离域退出，退出码: {}", exit_code);
    0
}

fn sys_sched_yield(regs: &mut GuestRegisters) -> u64 {
    0
}

fn sys_lseek(regs: &mut GuestRegisters) -> u64 {
    let fd = regs.rdi as i32;
    let offset = regs.rsi as i64;
    let whence = regs.rdx as i32;

    if fd < 0 {
        return (-EBADF) as u64;
    }

    let vfs = unsafe { get_vfs().as_mut() };
    if vfs.is_none() {
        return (-ENOENT) as u64;
    }
    let vfs = vfs.unwrap();

    let seek_from = match whence {
        SEEK_SET => SeekFrom::Start(offset as u64),
        SEEK_CUR => SeekFrom::Current(offset),
        SEEK_END => SeekFrom::End(offset),
        _ => return (-EINVAL) as u64,
    };

    match vfs.lseek(fd, offset, seek_from) {
        Ok(pos) => pos,
        Err(e) => (-e) as u64,
    }
}

fn sys_fstat(regs: &mut GuestRegisters) -> u64 {
    let fd = regs.rdi as i32;
    let statbuf_gpa = regs.rsi;

    if fd < 0 {
        return (-EBADF) as u64;
    }

    let vfs = unsafe { get_vfs().as_mut() };
    if vfs.is_none() {
        return (-ENOENT) as u64;
    }
    let vfs = vfs.unwrap();

    let mut mgr = crate::enclave::get_manager();
    let manager = match mgr.as_mut() {
        Some(m) => m,
        None => return (-EFAULT) as u64,
    };
    let cur = match manager.current_id() {
        Some(id) => id,
        None => return (-EFAULT) as u64,
    };
    let enclave = match manager.get_enclave_mut(cur) {
        Some(e) => e,
        None => return (-EFAULT) as u64,
    };

    let mut stat_buf: Stat = Default::default();
    
    match vfs.fstat(fd, &mut stat_buf, &enclave.ept) {
        Ok(()) => {
            let stat_bytes = unsafe {
                core::slice::from_raw_parts(
                    &stat_buf as *const Stat as *const u8,
                    core::mem::size_of::<Stat>(),
                )
            };
            copy_bytes_to_guest_gpa(&enclave.ept, statbuf_gpa, stat_bytes);
            0
        }
        Err(e) => (-e) as u64,
    }
}

fn sys_ioctl(regs: &mut GuestRegisters) -> u64 {
    let fd = regs.rdi as i32;
    let cmd = regs.rsi as u32;
    
    if fd < 0 {
        return (-EBADF) as u64;
    }
    
    const TIOCGWINSZ: u32 = 0x5413;
    
    match cmd {
        TIOCGWINSZ => {
            let mut mgr = crate::enclave::get_manager();
            let manager = match mgr.as_mut() {
                Some(m) => m,
                None => return (-EFAULT) as u64,
            };
            let cur = match manager.current_id() {
                Some(id) => id,
                None => return (-EFAULT) as u64,
            };
            let enclave = match manager.get_enclave_mut(cur) {
                Some(e) => e,
                None => return (-EFAULT) as u64,
            };
            
            let winsz = [0u8; 8];
            copy_bytes_to_guest_gpa(&enclave.ept, regs.rdx, &winsz);
            0
        }
        _ => (-ENOSYS) as u64,
    }
}

fn sys_access(regs: &mut GuestRegisters) -> u64 {
    let path_gpa = regs.rdi;
    let mode = regs.rsi as i32;

    let path = match read_string_from_guest(path_gpa, 256) {
        Some(p) => p,
        None => return (-ENOENT) as u64,
    };

    let vfs = unsafe { get_vfs().as_mut() };
    if vfs.is_none() {
        return (-ENOENT) as u64;
    }
    let vfs = vfs.unwrap();

    match vfs.access(&path, mode) {
        Ok(()) => 0,
        Err(e) => (-e) as u64,
    }
}

fn sys_getcwd(regs: &mut GuestRegisters) -> u64 {
    let buf_gpa = regs.rdi;
    let size = regs.rsi as usize;

    let vfs = unsafe { get_vfs().as_mut() };
    if vfs.is_none() {
        return (-ENOENT) as u64;
    }
    let vfs = vfs.unwrap();

    let cwd = vfs.getcwd();
    let cwd_bytes = cwd.as_bytes();
    
    if cwd_bytes.len() + 1 > size {
        return (-ERANGE) as u64;
    }

    let mut mgr = crate::enclave::get_manager();
    let manager = match mgr.as_mut() {
        Some(m) => m,
        None => return (-EFAULT) as u64,
    };
    let cur = match manager.current_id() {
        Some(id) => id,
        None => return (-EFAULT) as u64,
    };
    let enclave = match manager.get_enclave_mut(cur) {
        Some(e) => e,
        None => return (-EFAULT) as u64,
    };

    let mut buf = alloc::vec::Vec::with_capacity(cwd_bytes.len() + 1);
    buf.extend_from_slice(cwd_bytes);
    buf.push(0);
    
    copy_bytes_to_guest_gpa(&enclave.ept, buf_gpa, &buf);
    buf_gpa
}

fn sys_chdir(regs: &mut GuestRegisters) -> u64 {
    let path_gpa = regs.rdi;

    let path = match read_string_from_guest(path_gpa, 256) {
        Some(p) => p,
        None => return (-ENOENT) as u64,
    };

    let vfs = unsafe { get_vfs().as_mut() };
    if vfs.is_none() {
        return (-ENOENT) as u64;
    }
    let vfs = vfs.unwrap();

    match vfs.chdir(&path) {
        Ok(()) => 0,
        Err(e) => (-e) as u64,
    }
}

fn sys_fcntl(regs: &mut GuestRegisters) -> u64 {
    let fd = regs.rdi as i32;
    let cmd = regs.rsi as i32;
    let arg = regs.rdx;

    if fd < 0 {
        return (-EBADF) as u64;
    }

    let vfs = unsafe { get_vfs().as_mut() };
    if vfs.is_none() {
        return (-ENOENT) as u64;
    }
    let vfs = vfs.unwrap();

    match vfs.fcntl(fd, cmd, arg) {
        Ok(result) => result,
        Err(e) => (-e) as u64,
    }
}

fn sys_getdents64(regs: &mut GuestRegisters) -> u64 {
    0
}

fn sys_dup(regs: &mut GuestRegisters) -> u64 {
    let fd = regs.rdi as i32;

    if fd < 0 {
        return (-EBADF) as u64;
    }

    let vfs = unsafe { get_vfs().as_mut() };
    if vfs.is_none() {
        return (-ENOENT) as u64;
    }
    let vfs = vfs.unwrap();

    match vfs.dup(fd) {
        Ok(new_fd) => new_fd as u64,
        Err(e) => (-e) as u64,
    }
}

fn sys_dup2(regs: &mut GuestRegisters) -> u64 {
    let old_fd = regs.rdi as i32;
    let new_fd = regs.rsi as i32;

    if old_fd < 0 || new_fd < 0 {
        return (-EBADF) as u64;
    }

    let vfs = unsafe { get_vfs().as_mut() };
    if vfs.is_none() {
        return (-ENOENT) as u64;
    }
    let vfs = vfs.unwrap();

    match vfs.dup2(old_fd, new_fd) {
        Ok(fd) => fd as u64,
        Err(e) => (-e) as u64,
    }
}

fn sys_prctl(regs: &mut GuestRegisters) -> u64 {
    let option = regs.rdi as i32;
    match option {
        15 => 0,
        _ => EINVAL as u64,
    }
}

fn sys_getrandom(regs: &mut GuestRegisters) -> u64 {
    let buf_gpa = regs.rdi;
    let count = regs.rsi as usize;

    if count == 0 {
        return 0;
    }

    let mut mgr = crate::enclave::get_manager();
    let manager = match mgr.as_mut() {
        Some(m) => m,
        None => return EFAULT as u64,
    };
    let cur = match manager.current_id() {
        Some(id) => id,
        None => return EFAULT as u64,
    };
    let enclave = match manager.get_enclave_mut(cur) {
        Some(e) => e,
        None => return EFAULT as u64,
    };

    let mut seed = 0x12345678u64;
    let mut written = 0usize;
    let mut buf = [0u8; 256];
    let mut remaining = count;

    while remaining > 0 {
        let chunk = core::cmp::min(remaining, 256);
        for i in 0..chunk {
            seed = seed.wrapping_mul(1103515245).wrapping_add(12345);
            buf[i] = (seed >> 16) as u8;
        }
        let n = copy_bytes_to_guest_gpa(&enclave.ept, buf_gpa + written as u64, &buf[..chunk]);
        if n == 0 {
            break;
        }
        written += n;
        remaining -= n;
    }

    written as u64
}

fn sys_mremap(regs: &mut GuestRegisters) -> u64 {
    let old_address = regs.rdi;
    let old_size = regs.rsi;
    let new_size = regs.rdx;
    let flags = regs.r10;
    let new_address = regs.r8;

    if old_size == 0 || new_size == 0 {
        return (-EINVAL) as u64;
    }

    let may_move = (flags & MREMAP_MAYMOVE) != 0;
    let is_fixed = (flags & MREMAP_FIXED) != 0;
    let dont_unmap = (flags & MREMAP_DONTUNMAP) != 0;

    if is_fixed && !may_move {
        return (-EINVAL) as u64;
    }

    let old_aligned_size = (old_size + 0xFFF) & !0xFFF;
    let new_aligned_size = (new_size + 0xFFF) & !0xFFF;

    unsafe {
        if new_aligned_size <= old_aligned_size {
            return old_address;
        }

        let mut mgr = crate::enclave::get_manager();
        if let Some(manager) = mgr.as_mut() {
            if let Some(cur) = manager.current_id() {
                if let Some(enclave) = manager.get_enclave_mut(cur) {
                    let start_gpa = old_address + old_aligned_size;
                    let mut gpa = start_gpa;
                    let end_gpa = old_address + new_aligned_size;
                    
                    while gpa < end_gpa {
                        if let Some(frame) = crate::memory::allocate_frame() {
                            let hpa = frame.start_address();
                            let flags = crate::memory::ept::EptFlags::READ 
                                | crate::memory::ept::EptFlags::WRITE
                                | crate::memory::ept::EptFlags::EXECUTE
                                | crate::memory::ept::EptFlags::MEMORY_TYPE_WB;
                            enclave.ept.map(x86_64::PhysAddr::new(gpa), hpa, flags);
                        }
                        gpa += 4096;
                    }
                    
                    return old_address;
                }
            }
        }

        if may_move {
            let result_addr = MMAP_NEXT;
            MMAP_NEXT += new_aligned_size;

            let mut mgr = crate::enclave::get_manager();
            if let Some(manager) = mgr.as_mut() {
                if let Some(cur) = manager.current_id() {
                    if let Some(enclave) = manager.get_enclave_mut(cur) {
                        let mut copy_success = true;
                        let mut src_gpa = old_address & !0xFFF;
                        let mut dst_gpa = result_addr;
                        let copy_size = old_aligned_size.min(new_aligned_size);
                        let mut copied = 0u64;

                        while copied < copy_size {
                            if let Some(src_hpa) = enclave.ept.translate_gpa(x86_64::PhysAddr::new(src_gpa)) {
                                if let Some(dst_frame) = crate::memory::allocate_frame() {
                                    let dst_hpa = dst_frame.start_address();
                                    let flags = crate::memory::ept::EptFlags::READ 
                                        | crate::memory::ept::EptFlags::WRITE
                                        | crate::memory::ept::EptFlags::EXECUTE
                                        | crate::memory::ept::EptFlags::MEMORY_TYPE_WB;
                                    enclave.ept.map(x86_64::PhysAddr::new(dst_gpa), dst_hpa, flags);

                                    let src_virt = crate::memory::phys_to_virt(src_hpa);
                                    let dst_virt = crate::memory::phys_to_virt(dst_hpa);
                                    unsafe {
                                        core::ptr::copy_nonoverlapping(
                                            src_virt.as_u64() as *const u8,
                                            dst_virt.as_u64() as *mut u8,
                                            4096,
                                        );
                                    }
                                } else {
                                    copy_success = false;
                                    break;
                                }
                            }
                            src_gpa += 4096;
                            dst_gpa += 4096;
                            copied += 4096;
                        }

                        if copy_success && !dont_unmap {
                            let mut gpa = old_address & !0xFFF;
                            let end_gpa = gpa + old_aligned_size;
                            while gpa < end_gpa {
                                let _ = enclave.ept.unmap(x86_64::PhysAddr::new(gpa));
                                gpa += 4096;
                            }
                        }

                        if copy_success {
                            return result_addr;
                        }
                    }
                }
            }
        }
    }

    (-ENOMEM) as u64
}

fn read_tsc() -> u64 {
    let mut lo: u32 = 0;
    let mut hi: u32 = 0;
    unsafe {
        core::arch::asm!("lfence; rdtsc", out("eax") lo, out("edx") hi, options(nomem, nostack));
    }
    ((hi as u64) << 32) | (lo as u64)
}

fn get_current_time_ns() -> u64 {
    let tsc = read_tsc();
    let freq = 3_000_000_000u64;
    let secs = tsc / freq;
    let nanos = ((tsc % freq) * 1_000_000_000) / freq;
    let boot_time_sec = 1_700_000_000u64;
    (boot_time_sec + secs) * 1_000_000_000 + nanos
}

fn sys_clock_gettime(regs: &mut GuestRegisters) -> u64 {
    let clock_id = regs.rdi as i32;
    let tp_gpa = regs.rsi;

    if tp_gpa == 0 {
        return (-EFAULT) as u64;
    }

    match clock_id {
        CLOCK_REALTIME | CLOCK_MONOTONIC | CLOCK_MONOTONIC_RAW | 
        CLOCK_REALTIME_COARSE | CLOCK_MONOTONIC_COARSE | CLOCK_BOOTTIME => {
            let now_ns = get_current_time_ns();
            let tv_sec = now_ns / 1_000_000_000;
            let tv_nsec = now_ns % 1_000_000_000;

            let mut time_spec = [0u8; 16];
            time_spec[..8].copy_from_slice(&tv_sec.to_ne_bytes());
            time_spec[8..].copy_from_slice(&tv_nsec.to_ne_bytes());

            let mut mgr = crate::enclave::get_manager();
            if let Some(manager) = mgr.as_mut() {
                if let Some(cur) = manager.current_id() {
                    if let Some(enclave) = manager.get_enclave_mut(cur) {
                        copy_bytes_to_guest_gpa(&enclave.ept, tp_gpa, &time_spec);
                        return 0;
                    }
                }
            }
            (-EFAULT) as u64
        }
        CLOCK_PROCESS_CPUTIME_ID | CLOCK_THREAD_CPUTIME_ID => {
            let mut time_spec = [0u8; 16];
            let tv_sec = 0u64;
            let tv_nsec = 0u64;
            time_spec[..8].copy_from_slice(&tv_sec.to_ne_bytes());
            time_spec[8..].copy_from_slice(&tv_nsec.to_ne_bytes());

            let mut mgr = crate::enclave::get_manager();
            if let Some(manager) = mgr.as_mut() {
                if let Some(cur) = manager.current_id() {
                    if let Some(enclave) = manager.get_enclave_mut(cur) {
                        copy_bytes_to_guest_gpa(&enclave.ept, tp_gpa, &time_spec);
                        return 0;
                    }
                }
            }
            (-EFAULT) as u64
        }
        _ => (-EINVAL) as u64,
    }
}

fn sys_clock_getres(regs: &mut GuestRegisters) -> u64 {
    let clock_id = regs.rdi as i32;
    let res_gpa = regs.rsi;

    if res_gpa == 0 {
        return 0;
    }

    match clock_id {
        CLOCK_REALTIME | CLOCK_MONOTONIC | CLOCK_MONOTONIC_RAW |
        CLOCK_REALTIME_COARSE | CLOCK_MONOTONIC_COARSE | CLOCK_BOOTTIME |
        CLOCK_PROCESS_CPUTIME_ID | CLOCK_THREAD_CPUTIME_ID => {
            let tv_sec = 0u64;
            let tv_nsec = 1u64;
            let mut time_spec = [0u8; 16];
            time_spec[..8].copy_from_slice(&tv_sec.to_ne_bytes());
            time_spec[8..].copy_from_slice(&tv_nsec.to_ne_bytes());

            let mut mgr = crate::enclave::get_manager();
            if let Some(manager) = mgr.as_mut() {
                if let Some(cur) = manager.current_id() {
                    if let Some(enclave) = manager.get_enclave_mut(cur) {
                        copy_bytes_to_guest_gpa(&enclave.ept, res_gpa, &time_spec);
                        return 0;
                    }
                }
            }
            (-EFAULT) as u64
        }
        _ => (-EINVAL) as u64,
    }
}

fn sys_gettimeofday(regs: &mut GuestRegisters) -> u64 {
    let tv_gpa = regs.rdi;
    let tz_gpa = regs.rsi;

    if tv_gpa != 0 {
        let now_ns = get_current_time_ns();
        let tv_sec = now_ns / 1_000_000_000;
        let tv_usec = (now_ns % 1_000_000_000) / 1000;

        let mut timeval = [0u8; 16];
        timeval[..8].copy_from_slice(&tv_sec.to_ne_bytes());
        timeval[8..].copy_from_slice(&tv_usec.to_ne_bytes());

        let mut mgr = crate::enclave::get_manager();
        if let Some(manager) = mgr.as_mut() {
            if let Some(cur) = manager.current_id() {
                if let Some(enclave) = manager.get_enclave_mut(cur) {
                    copy_bytes_to_guest_gpa(&enclave.ept, tv_gpa, &timeval);
                }
            }
        }
    }

    if tz_gpa != 0 {
        let tz = [0u8; 8];
        let mut mgr = crate::enclave::get_manager();
        if let Some(manager) = mgr.as_mut() {
            if let Some(cur) = manager.current_id() {
                if let Some(enclave) = manager.get_enclave_mut(cur) {
                    copy_bytes_to_guest_gpa(&enclave.ept, tz_gpa, &tz);
                }
            }
        }
    }

    0
}

fn sys_nanosleep(regs: &mut GuestRegisters) -> u64 {
    let req_gpa = regs.rdi;
    let rem_gpa = regs.rsi;

    if req_gpa == 0 {
        return (-EFAULT) as u64;
    }

    let mut mgr = crate::enclave::get_manager();
    let manager = match mgr.as_mut() {
        Some(m) => m,
        None => return (-EFAULT) as u64,
    };
    let cur = match manager.current_id() {
        Some(id) => id,
        None => return (-EFAULT) as u64,
    };
    let enclave = match manager.get_enclave_mut(cur) {
        Some(e) => e,
        None => return (-EFAULT) as u64,
    };

    let mut req = [0u8; 16];
    let n = copy_guest_gpa_bytes(&enclave.ept, req_gpa, &mut req);
    if n < 16 {
        return (-EFAULT) as u64;
    }

    let tv_sec = u64::from_ne_bytes(req[..8].try_into().unwrap());
    let tv_nsec = u64::from_ne_bytes(req[8..].try_into().unwrap());

    if tv_nsec >= 1_000_000_000 {
        return (-EINVAL) as u64;
    }

    if rem_gpa != 0 {
        let zero = [0u8; 16];
        copy_bytes_to_guest_gpa(&enclave.ept, rem_gpa, &zero);
    }

    0
}

fn read_argv_from_guest(ept: &EptManager, argv_gpa: u64, max_count: usize) -> Vec<String> {
    let mut argv = Vec::new();
    let mut index = 0usize;
    
    loop {
        if index >= max_count {
            break;
        }
        
        let mut ptr_buf = [0u8; 8];
        let n = copy_guest_gpa_bytes(ept, argv_gpa + (index * 8) as u64, &mut ptr_buf);
        if n < 8 {
            break;
        }
        
        let ptr = u64::from_ne_bytes(ptr_buf);
        if ptr == 0 {
            break;
        }
        
        if let Some(s) = read_string_from_ptr(ept, ptr, 4096) {
            argv.push(s);
        }
        
        index += 1;
    }
    
    argv
}

fn read_string_from_ptr(ept: &EptManager, gpa: u64, max_len: usize) -> Option<String> {
    let mut buf = [0u8; 256];
    let mut result = String::new();
    let mut offset = 0u64;
    
    loop {
        let n = copy_guest_gpa_bytes(ept, gpa + offset, &mut buf);
        if n == 0 {
            break;
        }
        
        for i in 0..n {
            if buf[i] == 0 {
                return Some(result);
            }
            if buf[i].is_ascii_graphic() || buf[i] == b'/' || buf[i] == b'.' || 
               buf[i] == b' ' || buf[i] == b'-' || buf[i] == b'_' || buf[i] == b':' ||
               buf[i] == b'=' || buf[i] == b'@' || buf[i] == b'+' {
                result.push(buf[i] as char);
            } else {
                return None;
            }
        }
        
        offset += n as u64;
        if result.len() >= max_len {
            break;
        }
    }
    
    Some(result)
}

fn sys_execve(regs: &mut GuestRegisters) -> u64 {
    let path_gpa = regs.rdi;
    let argv_gpa = regs.rsi;
    let envp_gpa = regs.rdx;
    
    let path = match read_string_from_guest(path_gpa, 4096) {
        Some(p) => p,
        None => return (-ENOENT) as u64,
    };
    
    let mut mgr = crate::enclave::get_manager();
    let manager = match mgr.as_mut() {
        Some(m) => m,
        None => return (-EFAULT) as u64,
    };
    let cur = match manager.current_id() {
        Some(id) => id,
        None => return (-EFAULT) as u64,
    };
    let enclave = match manager.get_enclave_mut(cur) {
        Some(e) => e,
        None => return (-EFAULT) as u64,
    };
    
    let vfs = unsafe { get_vfs().as_mut() };
    if vfs.is_none() {
        return (-ENOENT) as u64;
    }
    let vfs = vfs.unwrap();
    
    let flags = OpenFlags::RDONLY;
    let mode = FileMode::from_bits_truncate(0o755);
    
    let fd = match vfs.open(&path, flags, mode) {
        Ok(fd) => fd,
        Err(e) => return (-e) as u64,
    };
    
    let mut elf_data = Vec::new();
    let mut chunk_buf = [0u8; 4096];
    
    loop {
        match vfs.read(fd, &mut chunk_buf, &enclave.ept) {
            Ok(0) => break,
            Ok(n) => elf_data.extend_from_slice(&chunk_buf[..n]),
            Err(e) => {
                let _ = vfs.close(fd);
                return (-e) as u64;
            }
        }
    }
    
    let _ = vfs.close(fd);
    
    if elf_data.len() < core::mem::size_of::<crate::vm::elf::Elf64Ehdr>() {
        return (-ENOEXEC) as u64;
    }
    
    let ehdr = match crate::vm::elf::ElfLoader::validate_elf(&elf_data) {
        Ok(e) => e,
        Err(_) => return (-ENOEXEC) as u64,
    };
    
    crate::log_info!("execve: 执行程序 '{}', 入口点 {:#x}", path, ehdr.entry_point());
    
    if ehdr.e_type == crate::vm::elf::ET_DYN {
        crate::log_info!("execve: 检测到动态链接可执行文件 (PIE)");
    }
    
    let load_offset = if ehdr.e_type == crate::vm::elf::ET_DYN {
        0x4000_0000
    } else {
        0
    };
    
    let elf_loader = crate::vm::elf::ElfLoader::new();
    let load_result = elf_loader.load_elf(&elf_data, &mut enclave.ept, load_offset);
    
    match load_result {
        Ok(info) => {
            crate::log_info!("execve: ELF 加载成功: 入口={:#x}, 范围={:#x}-{:#x}", 
                info.entry_point, info.lowest_vaddr, info.highest_vaddr);
            
            let stack_pages = 4u64;
            let stack_base = 0x7FFF_0000;
            let stack_size = stack_pages * 4096;
            
            let mut current_gpa = stack_base - stack_size;
            let end_gpa = stack_base;
            
            while current_gpa < end_gpa {
                if let Some(frame) = crate::memory::allocate_frame() {
                    let hpa = frame.start_address();
                    let flags = crate::memory::ept::EptFlags::READ 
                        | crate::memory::ept::EptFlags::WRITE
                        | crate::memory::ept::EptFlags::MEMORY_TYPE_WB;
                    enclave.ept.map(x86_64::PhysAddr::new(current_gpa), hpa, flags);
                }
                current_gpa += 4096;
            }
            
            regs.rax = 0;
            regs.rsp = stack_base;
            regs.rip = info.entry_point;
            regs.rbp = 0;
            regs.rbx = 0;
            regs.rcx = 0;
            regs.rdx = 0;
            regs.rsi = 0;
            regs.rdi = 0;
            regs.r8 = 0;
            regs.r9 = 0;
            regs.r10 = 0;
            regs.r11 = 0;
            regs.r12 = 0;
            regs.r13 = 0;
            regs.r14 = 0;
            regs.r15 = 0;
            
            unsafe { 
                BRK_CURRENT = 0x4000_0000;
                MMAP_NEXT = 0x7000_0000;
            }
            
            crate::log_info!("execve: 程序执行环境已设置，入口点 {:#x}", info.entry_point);
            0
        }
        Err(e) => {
            crate::log_error!("execve: ELF 加载失败: {}", e);
            (-ENOEXEC) as u64
        }
    }
}

fn sys_clone(regs: &mut GuestRegisters) -> u64 {
    let flags = regs.rdi;
    let stack = regs.rsi;
    let parent_tid = regs.rdx;
    let child_tid = regs.r8;
    let tls = regs.r10;
    
    let is_thread = (flags & CLONE_THREAD) != 0;
    let share_vm = (flags & CLONE_VM) != 0;
    let share_files = (flags & CLONE_FILES) != 0;
    let share_fs = (flags & CLONE_FS) != 0;
    
    crate::log_info!("clone: flags={:#x}, stack={:#x}, is_thread={}, share_vm={}",
        flags, stack, is_thread, share_vm);
    
    if share_vm && is_thread {
        crate::log_info!("clone: 创建线程 (轻量级进程)");
        return 1;
    }
    
    let mut pm_guard = PROCESS_MANAGER.lock();
    let pm = pm_guard.as_mut();
    if pm.is_none() {
        return (-ENOMEM) as u64;
    }
    let pm = pm.unwrap();
    
    let parent_pid = pm.current_pid;
    
    let child_pid = match pm.create_process(parent_pid) {
        Some(pid) => pid,
        None => return (-EAGAIN) as u64,
    };
    
    crate::log_info!("clone: 创建新进程，parent_pid={}, child_pid={}", parent_pid, child_pid);
    
    child_pid as u64
}

fn sys_fork(regs: &mut GuestRegisters) -> u64 {
    crate::log_info!("fork: 创建子进程");
    
    let mut pm_guard = PROCESS_MANAGER.lock();
    let pm = pm_guard.as_mut();
    if pm.is_none() {
        return (-ENOMEM) as u64;
    }
    let pm = pm.unwrap();
    
    let parent_pid = pm.current_pid;
    
    let child_pid = match pm.create_process(parent_pid) {
        Some(pid) => pid,
        None => return (-EAGAIN) as u64,
    };
    
    crate::log_info!("fork: 子进程创建成功，child_pid={}", child_pid);
    
    child_pid as u64
}

fn sys_vfork(regs: &mut GuestRegisters) -> u64 {
    crate::log_info!("vfork: 创建子进程 (vfork)");
    sys_fork(regs)
}

fn sys_wait4(regs: &mut GuestRegisters) -> u64 {
    let pid = regs.rdi as i32;
    let wstatus_gpa = regs.rsi;
    let options = regs.rdx as i32;
    let rusage_gpa = regs.r10;
    
    let mut pm_guard = PROCESS_MANAGER.lock();
    let pm = pm_guard.as_mut();
    if pm.is_none() {
        return (-ECHILD) as u64;
    }
    let pm = pm.unwrap();
    
    let current_pid = pm.current_pid;
    
    let zombie_pid = if pid == -1 {
        pm.has_zombie_child(current_pid)
    } else if pid > 0 {
        if let Some(proc) = pm.get(pid) {
            if proc.ppid == current_pid && proc.state == ProcessState::Zombie {
                Some(pid)
            } else {
                None
            }
        } else {
            None
        }
    } else {
        None
    };
    
    match zombie_pid {
        Some(zpid) => {
            let exit_code = pm.remove_zombie(zpid).unwrap_or(0);
            
            if wstatus_gpa != 0 {
                let mut mgr = crate::enclave::get_manager();
                if let Some(manager) = mgr.as_mut() {
                    if let Some(cur) = manager.current_id() {
                        if let Some(enclave) = manager.get_enclave_mut(cur) {
                            let status = ((exit_code & 0xFF) << 8) as u32;
                            let status_bytes = status.to_ne_bytes();
                            copy_bytes_to_guest_gpa(&enclave.ept, wstatus_gpa, &status_bytes);
                        }
                    }
                }
            }
            
            crate::log_info!("wait4: 回收子进程 {}，退出码 {}", zpid, exit_code);
            zpid as u64
        }
        None => {
            crate::log_debug!("wait4: 没有可回收的子进程");
            0
        }
    }
}

fn sys_pipe(regs: &mut GuestRegisters) -> u64 {
    let pipefd_gpa = regs.rdi;
    let flags = regs.rsi as i32;
    
    unsafe {
        if PIPES.is_none() {
            init_pipes();
        }
    }
    
    let pipe = Arc::new(Mutex::new(Pipe::new()));
    
    let read_fd = 100;
    let write_fd = 101;
    
    unsafe {
        if let Some(pipes) = PIPES.as_mut() {
            pipes.insert(read_fd, pipe.clone());
            pipes.insert(write_fd, pipe);
        }
    }
    
    let mut mgr = crate::enclave::get_manager();
    let manager = match mgr.as_mut() {
        Some(m) => m,
        None => return (-EFAULT) as u64,
    };
    let cur = match manager.current_id() {
        Some(id) => id,
        None => return (-EFAULT) as u64,
    };
    let enclave = match manager.get_enclave_mut(cur) {
        Some(e) => e,
        None => return (-EFAULT) as u64,
    };
    
    let mut fd_buf = [0u8; 8];
    fd_buf[..4].copy_from_slice(&(read_fd as i32).to_ne_bytes());
    copy_bytes_to_guest_gpa(&enclave.ept, pipefd_gpa, &fd_buf);
    
    fd_buf[..4].copy_from_slice(&(write_fd as i32).to_ne_bytes());
    copy_bytes_to_guest_gpa(&enclave.ept, pipefd_gpa + 4, &fd_buf);
    
    crate::log_info!("pipe: 创建管道，read_fd={}, write_fd={}", read_fd, write_fd);
    
    0
}
