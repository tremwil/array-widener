#![forbid(unsafe_op_in_unsafe_fn)]

pub mod arena;
pub mod array_widener;
pub mod cfg;
pub mod iced_ext;
pub mod rwe_buffer;
pub mod thunk;
pub mod trampoline;
pub mod widenable;
mod winapi_utils;

pub use iced_x86;
pub use widenable::Widenable;
