// src/serial.rs
use uart_16550::SerialPort;
use spin::Mutex;
use lazy_static::lazy_static;

lazy_static! {
    pub static ref SERIAL1: Mutex<SerialPort> = {
        let mut serial_port = unsafe { SerialPort::new(0x3F8) };
        serial_port.init();
        Mutex::new(serial_port)
    };
}

#[doc(hidden)]
pub fn _print(args: ::core::fmt::Arguments) {
    use core::fmt::Write;
    SERIAL1.lock().write_fmt(args).expect("串口输出失败");
}

#[macro_export]
macro_rules! serial_print {
    ($($arg:tt)*) => {
        $crate::serial::_print(format_args!($($arg)*));
    };
}

#[macro_export]
macro_rules! serial_println {
    () => ($crate::serial_print!("\n"));
    ($fmt:expr) => ($crate::serial_print!(concat!($fmt, "\n")));
    ($fmt:expr, $($arg:tt)*) => ($crate::serial_print!(
        concat!($fmt, "\n"), $($arg)*
    ));
}

#[derive(PartialEq, PartialOrd)]
pub enum LogLevel {
    Debug,
    Info,
    Warn,
    Error,
}

pub const CURRENT_LOG_LEVEL: LogLevel = LogLevel::Info;

#[macro_export]
macro_rules! log_debug {
    ($($arg:tt)*) => {
        if $crate::serial::CURRENT_LOG_LEVEL <= $crate::serial::LogLevel::Debug {
            $crate::serial_println!("[调试] {}", format_args!($($arg)*));
        }
    };
}

#[macro_export]
macro_rules! log_info {
    ($($arg:tt)*) => {
        if $crate::serial::CURRENT_LOG_LEVEL <= $crate::serial::LogLevel::Info {
            $crate::serial_println!("[信息] {}", format_args!($($arg)*));
        }
    };
}

#[macro_export]
macro_rules! log_warn {
    ($($arg:tt)*) => {
        if $crate::serial::CURRENT_LOG_LEVEL <= $crate::serial::LogLevel::Warn {
            $crate::serial_println!("[警告] {}", format_args!($($arg)*));
        }
    };
}

#[macro_export]
macro_rules! log_error {
    ($($arg:tt)*) => {
        if $crate::serial::CURRENT_LOG_LEVEL <= $crate::serial::LogLevel::Error {
            $crate::serial_println!("[错误] {}", format_args!($($arg)*));
        }
    };
}