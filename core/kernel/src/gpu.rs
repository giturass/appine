//! Host interface for a Venus render node. Each open file description owns one context.
use std::os::fd::OwnedFd;
use std::ptr::NonNull;
use std::sync::Arc;

use crate::errno::Errno;

/// A renderer that has passed the host capability probe.
pub trait Renderer: Send + Sync {
    /// The Venus capset reported by the decoder packaged with this renderer.
    fn capset(&self) -> &[u8];
    /// Starts an independent command stream and resource table.
    fn open(&self) -> Result<Arc<dyn Context>, Errno>;
}

/// Operations on one renderer context. Calls can originate from different guest threads.
pub trait Context: Send + Sync {
    /// Creates a host-visible blob and returns its coherent CPU mapping.
    fn create(&self, resource: u32, blob: u64, size: u64) -> Result<Arc<dyn Mapping>, Errno>;
    /// Retains the supplied buffers until the ring completes. An optional output fence
    /// becomes readable on retirement. Dropping the last buffer reference detaches it.
    fn submit(
        &self,
        ring: u32,
        command: &[u8],
        fence: bool,
        buffers: Vec<Arc<dyn Mapping>>,
    ) -> Result<Option<OwnedFd>, Errno>;
}

/// CPU mapping shared by the renderer and the guest MMU.
///
/// # Safety
/// The address must remain page-aligned, readable and writable for the reported size until
/// the final owner drops it. The host must not create Rust references to the shared contents.
pub unsafe trait Mapping: Send + Sync {
    /// Base host address.
    fn base(&self) -> NonNull<u8>;
    /// Accessible bytes from the base.
    fn size(&self) -> usize;
}
