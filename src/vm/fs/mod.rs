pub mod file;
pub mod devfs;
pub mod ramfs;
pub mod procfs;

pub use file::{FileHandle, FileOps, SeekFrom, OpenFlags, FileMode};
pub use ramfs::RamFileSystem;
pub use procfs::{ProcVersion, ProcCmdline, ProcCpuinfo, ProcMeminfo, ProcUptime, ProcLoadavg, ProcStat};

use crate::memory::ept::EptManager;
use alloc::boxed::Box;
use alloc::format;
use alloc::string::ToString;
use file::FileDescriptorTable;
use devfs::DevFs;

pub struct VirtualFileSystem {
    fd_table: FileDescriptorTable,
    dev_fs: DevFs,
    root_fs: RamFileSystem,
    cwd: &'static str,
}

impl VirtualFileSystem {
    pub fn new() -> Self {
        let mut vfs = Self {
            fd_table: FileDescriptorTable::new(),
            dev_fs: DevFs::new(),
            root_fs: RamFileSystem::new(),
            cwd: "/",
        };
        
        vfs.init_stdio();
        vfs
    }

    fn init_stdio(&mut self) {
        let stdin = FileHandle::new(
            "stdin",
            OpenFlags::RDONLY,
            FileMode::from_bits_truncate(0o666),
            Box::new(Stdin),
        );
        let stdout = FileHandle::new(
            "stdout",
            OpenFlags::WRONLY,
            FileMode::from_bits_truncate(0o666),
            Box::new(Stdout),
        );
        let stderr = FileHandle::new(
            "stderr",
            OpenFlags::WRONLY,
            FileMode::from_bits_truncate(0o666),
            Box::new(Stderr),
        );

        self.fd_table.allocate_with_fd(0, stdin);
        self.fd_table.allocate_with_fd(1, stdout);
        self.fd_table.allocate_with_fd(2, stderr);
    }

    pub fn open(&mut self, path: &str, flags: OpenFlags, mode: FileMode) -> Result<i32, i64> {
        if path.starts_with("/dev/") {
            return self.dev_fs.open(&path[5..], flags, mode)
                .and_then(|handle| self.fd_table.allocate(handle))
                .ok_or(-crate::vm::syscall::linux::ENOENT);
        }

        if path.starts_with("/proc/") || path == "/proc" {
            return self.open_proc(path, flags, mode)
                .and_then(|handle| self.fd_table.allocate(handle))
                .ok_or(-crate::vm::syscall::linux::ENOENT);
        }

        self.root_fs.open(path, flags, mode)
            .and_then(|handle| self.fd_table.allocate(handle))
            .ok_or(-crate::vm::syscall::linux::ENOENT)
    }

    fn open_proc(&mut self, path: &str, _flags: OpenFlags, _mode: FileMode) -> Option<FileHandle> {
        match path {
            "/proc/version" => Some(FileHandle::new(
                "/proc/version",
                OpenFlags::RDONLY,
                FileMode::from_bits_truncate(0o444),
                Box::new(ProcVersion),
            )),
            "/proc/cmdline" => Some(FileHandle::new(
                "/proc/cmdline",
                OpenFlags::RDONLY,
                FileMode::from_bits_truncate(0o444),
                Box::new(ProcCmdline),
            )),
            "/proc/cpuinfo" => Some(FileHandle::new(
                "/proc/cpuinfo",
                OpenFlags::RDONLY,
                FileMode::from_bits_truncate(0o444),
                Box::new(ProcCpuinfo),
            )),
            "/proc/meminfo" => Some(FileHandle::new(
                "/proc/meminfo",
                OpenFlags::RDONLY,
                FileMode::from_bits_truncate(0o444),
                Box::new(ProcMeminfo),
            )),
            "/proc/uptime" => Some(FileHandle::new(
                "/proc/uptime",
                OpenFlags::RDONLY,
                FileMode::from_bits_truncate(0o444),
                Box::new(ProcUptime),
            )),
            "/proc/loadavg" => Some(FileHandle::new(
                "/proc/loadavg",
                OpenFlags::RDONLY,
                FileMode::from_bits_truncate(0o444),
                Box::new(ProcLoadavg),
            )),
            "/proc/stat" => Some(FileHandle::new(
                "/proc/stat",
                OpenFlags::RDONLY,
                FileMode::from_bits_truncate(0o444),
                Box::new(ProcStat),
            )),
            _ => None,
        }
    }

    pub fn close(&mut self, fd: i32) -> Result<(), i64> {
        if fd < 0 {
            return Err(-crate::vm::syscall::linux::EBADF);
        }
        self.fd_table.deallocate(fd)
            .ok_or(-crate::vm::syscall::linux::EBADF)?;
        Ok(())
    }

    pub fn read(&mut self, fd: i32, buf: &mut [u8], ept: &EptManager) -> Result<usize, i64> {
        if fd < 0 {
            return Err(-crate::vm::syscall::linux::EBADF);
        }
        let handle = self.fd_table.get_mut(fd as usize)
            .ok_or(-crate::vm::syscall::linux::EBADF)?;
        handle.read(buf, ept)
    }

    pub fn write(&mut self, fd: i32, buf: &[u8], ept: &EptManager) -> Result<usize, i64> {
        if fd < 0 {
            return Err(-crate::vm::syscall::linux::EBADF);
        }
        let handle = self.fd_table.get_mut(fd as usize)
            .ok_or(-crate::vm::syscall::linux::EBADF)?;
        handle.write(buf, ept)
    }

    pub fn lseek(&mut self, fd: i32, offset: i64, whence: SeekFrom) -> Result<u64, i64> {
        if fd < 0 {
            return Err(-crate::vm::syscall::linux::EBADF);
        }
        let handle = self.fd_table.get_mut(fd as usize)
            .ok_or(-crate::vm::syscall::linux::EBADF)?;
        handle.lseek(offset, whence)
    }

    pub fn fstat(&mut self, fd: i32, stat_buf: &mut Stat, ept: &EptManager) -> Result<(), i64> {
        if fd < 0 {
            return Err(-crate::vm::syscall::linux::EBADF);
        }
        let handle = self.fd_table.get_mut(fd as usize)
            .ok_or(-crate::vm::syscall::linux::EBADF)?;
        handle.fstat(stat_buf, ept)
    }

    pub fn dup(&mut self, fd: i32) -> Result<i32, i64> {
        if fd < 0 {
            return Err(-crate::vm::syscall::linux::EBADF);
        }
        let handle = self.fd_table.get(fd as usize)
            .ok_or(-crate::vm::syscall::linux::EBADF)?;
        let cloned = handle.clone();
        self.fd_table.allocate(cloned)
            .ok_or(-crate::vm::syscall::linux::EMFILE)
    }

    pub fn dup2(&mut self, old_fd: i32, new_fd: i32) -> Result<i32, i64> {
        if old_fd < 0 || new_fd < 0 {
            return Err(-crate::vm::syscall::linux::EBADF);
        }
        
        if old_fd == new_fd {
            return Ok(new_fd);
        }

        let cloned = {
            let handle = self.fd_table.get(old_fd as usize)
                .ok_or(-crate::vm::syscall::linux::EBADF)?;
            handle.clone()
        };

        if self.fd_table.get(new_fd as usize).is_some() {
            let _ = self.fd_table.deallocate(new_fd);
        }

        self.fd_table.allocate_with_fd(new_fd as usize, cloned);
        Ok(new_fd)
    }

    pub fn fcntl(&mut self, fd: i32, cmd: i32, arg: u64) -> Result<u64, i64> {
        if fd < 0 {
            return Err(-crate::vm::syscall::linux::EBADF);
        }
        let _handle = self.fd_table.get(fd as usize)
            .ok_or(-crate::vm::syscall::linux::EBADF)?;
        
        const F_DUPFD: i32 = 0;
        const F_GETFD: i32 = 1;
        const F_SETFD: i32 = 2;
        const F_GETFL: i32 = 3;
        const F_SETFL: i32 = 4;

        match cmd {
            F_DUPFD => {
                let min_fd = arg as i32;
                if min_fd < 0 {
                    return Err(-crate::vm::syscall::linux::EINVAL);
                }
                self.dup(fd)
                    .and_then(|new_fd| {
                        if new_fd >= min_fd {
                            Ok(new_fd as u64)
                        } else {
                            self.close(new_fd)?;
                            Err(-crate::vm::syscall::linux::EINVAL)
                        }
                    })
            }
            F_GETFD => Ok(0),
            F_SETFD => Ok(0),
            F_GETFL => Ok(0),
            F_SETFL => Ok(0),
            _ => Err(-crate::vm::syscall::linux::EINVAL),
        }
    }

    pub fn getcwd(&self) -> &str {
        self.cwd
    }

    pub fn chdir(&mut self, path: &str) -> Result<(), i64> {
        if path.starts_with('/') {
            if self.dev_fs.exists(&path[1..]) || self.root_fs.exists(path) || self.proc_path_exists(path) {
                let owned_path = path.to_string();
                self.cwd = Box::leak(owned_path.into_boxed_str());
                Ok(())
            } else {
                Err(-crate::vm::syscall::linux::ENOENT)
            }
        } else {
            let new_path = if self.cwd.ends_with('/') {
                format!("{}{}", self.cwd, path)
            } else {
                format!("{}/{}", self.cwd, path)
            };
            if self.dev_fs.exists(&new_path[1..]) || self.root_fs.exists(&new_path) || self.proc_path_exists(&new_path) {
                self.cwd = Box::leak(new_path.into_boxed_str());
                Ok(())
            } else {
                Err(-crate::vm::syscall::linux::ENOENT)
            }
        }
    }

    pub fn access(&self, path: &str, _mode: i32) -> Result<(), i64> {
        if path.starts_with("/dev/") {
            if self.dev_fs.exists(&path[5..]) {
                Ok(())
            } else {
                Err(-crate::vm::syscall::linux::ENOENT)
            }
        } else if path.starts_with("/proc/") || path == "/proc" {
            if self.proc_path_exists(path) {
                Ok(())
            } else {
                Err(-crate::vm::syscall::linux::ENOENT)
            }
        } else if self.root_fs.exists(path) {
            Ok(())
        } else {
            Err(-crate::vm::syscall::linux::ENOENT)
        }
    }

    fn proc_path_exists(&self, path: &str) -> bool {
        matches!(path, 
            "/proc" | 
            "/proc/version" | 
            "/proc/cmdline" | 
            "/proc/cpuinfo" | 
            "/proc/meminfo" | 
            "/proc/uptime" | 
            "/proc/loadavg" | 
            "/proc/stat"
        )
    }
}

impl Default for VirtualFileSystem {
    fn default() -> Self {
        Self::new()
    }
}

pub struct Stdin;

impl FileOps for Stdin {
    fn read(&mut self, buf: &mut [u8], _ept: &EptManager) -> Result<usize, i64> {
        Ok(0)
    }

    fn write(&mut self, _buf: &[u8], _ept: &EptManager) -> Result<usize, i64> {
        Err(-crate::vm::syscall::linux::EBADF)
    }

    fn lseek(&mut self, _offset: i64, _whence: SeekFrom) -> Result<u64, i64> {
        Err(-crate::vm::syscall::linux::ESPIPE)
    }

    fn fstat(&mut self, stat_buf: &mut Stat, _ept: &EptManager) -> Result<(), i64> {
        stat_buf.st_dev = 0;
        stat_buf.st_ino = 0;
        stat_buf.st_mode = 0o444 | 0o010000;
        stat_buf.st_nlink = 1;
        stat_buf.st_uid = 0;
        stat_buf.st_gid = 0;
        stat_buf.st_rdev = 0;
        stat_buf.st_size = 0;
        stat_buf.st_blksize = 4096;
        stat_buf.st_blocks = 0;
        stat_buf.st_atime = 0;
        stat_buf.st_atime_nsec = 0;
        stat_buf.st_mtime = 0;
        stat_buf.st_mtime_nsec = 0;
        stat_buf.st_ctime = 0;
        stat_buf.st_ctime_nsec = 0;
        Ok(())
    }

    fn clone(&self) -> Box<dyn FileOps> {
        Box::new(Stdin)
    }
}

pub struct Stdout;

impl FileOps for Stdout {
    fn read(&mut self, _buf: &mut [u8], _ept: &EptManager) -> Result<usize, i64> {
        Err(-crate::vm::syscall::linux::EBADF)
    }

    fn write(&mut self, buf: &[u8], _ept: &EptManager) -> Result<usize, i64> {
        for &byte in buf {
            if byte == b'\n' || byte == b'\r' || byte == b'\t' || (byte >= 0x20 && byte < 0x7f) {
                crate::serial_print!("{}", byte as char);
            }
        }
        Ok(buf.len())
    }

    fn lseek(&mut self, _offset: i64, _whence: SeekFrom) -> Result<u64, i64> {
        Err(-crate::vm::syscall::linux::ESPIPE)
    }

    fn fstat(&mut self, stat_buf: &mut Stat, _ept: &EptManager) -> Result<(), i64> {
        stat_buf.st_dev = 0;
        stat_buf.st_ino = 1;
        stat_buf.st_mode = 0o222 | 0o010000;
        stat_buf.st_nlink = 1;
        stat_buf.st_uid = 0;
        stat_buf.st_gid = 0;
        stat_buf.st_rdev = 0;
        stat_buf.st_size = 0;
        stat_buf.st_blksize = 4096;
        stat_buf.st_blocks = 0;
        stat_buf.st_atime = 0;
        stat_buf.st_atime_nsec = 0;
        stat_buf.st_mtime = 0;
        stat_buf.st_mtime_nsec = 0;
        stat_buf.st_ctime = 0;
        stat_buf.st_ctime_nsec = 0;
        Ok(())
    }

    fn clone(&self) -> Box<dyn FileOps> {
        Box::new(Stdout)
    }
}

pub struct Stderr;

impl FileOps for Stderr {
    fn read(&mut self, _buf: &mut [u8], _ept: &EptManager) -> Result<usize, i64> {
        Err(-crate::vm::syscall::linux::EBADF)
    }

    fn write(&mut self, buf: &[u8], _ept: &EptManager) -> Result<usize, i64> {
        for &byte in buf {
            if byte == b'\n' || byte == b'\r' || byte == b'\t' || (byte >= 0x20 && byte < 0x7f) {
                crate::serial_print!("{}", byte as char);
            }
        }
        Ok(buf.len())
    }

    fn lseek(&mut self, _offset: i64, _whence: SeekFrom) -> Result<u64, i64> {
        Err(-crate::vm::syscall::linux::ESPIPE)
    }

    fn fstat(&mut self, stat_buf: &mut Stat, _ept: &EptManager) -> Result<(), i64> {
        stat_buf.st_dev = 0;
        stat_buf.st_ino = 2;
        stat_buf.st_mode = 0o222 | 0o010000;
        stat_buf.st_nlink = 1;
        stat_buf.st_uid = 0;
        stat_buf.st_gid = 0;
        stat_buf.st_rdev = 0;
        stat_buf.st_size = 0;
        stat_buf.st_blksize = 4096;
        stat_buf.st_blocks = 0;
        stat_buf.st_atime = 0;
        stat_buf.st_atime_nsec = 0;
        stat_buf.st_mtime = 0;
        stat_buf.st_mtime_nsec = 0;
        stat_buf.st_ctime = 0;
        stat_buf.st_ctime_nsec = 0;
        Ok(())
    }

    fn clone(&self) -> Box<dyn FileOps> {
        Box::new(Stderr)
    }
}

#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct Stat {
    pub st_dev: u64,
    pub st_ino: u64,
    pub st_nlink: u64,
    pub st_mode: u32,
    pub st_uid: u32,
    pub st_gid: u32,
    pub __pad0: u32,
    pub st_rdev: u64,
    pub st_size: i64,
    pub st_blksize: i64,
    pub st_blocks: i64,
    pub st_atime: i64,
    pub st_atime_nsec: i64,
    pub st_mtime: i64,
    pub st_mtime_nsec: i64,
    pub st_ctime: i64,
    pub st_ctime_nsec: i64,
    pub __unused: [i64; 3],
}

pub static mut GLOBAL_VFS: Option<VirtualFileSystem> = None;

pub fn init_vfs() {
    unsafe {
        GLOBAL_VFS = Some(VirtualFileSystem::new());
    }
}

pub fn get_vfs() -> &'static mut Option<VirtualFileSystem> {
    unsafe { &mut GLOBAL_VFS }
}
