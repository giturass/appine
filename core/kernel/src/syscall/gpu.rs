//! The arm64 DRM render-node ABI used by Mesa Venus. No guest pointer crosses the host interface.
use std::cell::Cell;
use std::collections::BTreeMap;
use std::rc::Rc;
use std::sync::Arc;

use super::{SysResult, get, put};
use crate::cell::RefCell;
use crate::errno::Errno;
use crate::fd::{FileKind, OpenFile, oflags};
use crate::gpu::{Context, Mapping, Renderer};
use crate::kernel::Cx;
use crate::uaccess::UserSlice;

const DRM_VERSION: u32 = 0xc0406400;
const DRM_GET_CAP: u32 = 0xc010640c;
const DRM_GEM_CLOSE: u32 = 0x40086409;
const VIRTGPU_GETPARAM: u32 = 0xc0106443;
const VIRTGPU_GET_CAPS: u32 = 0xc0186449;
const VIRTGPU_CONTEXT_INIT: u32 = 0xc010644b;
const VIRTGPU_RESOURCE_CREATE_BLOB: u32 = 0xc030644a;
const VIRTGPU_MAP: u32 = 0xc0106441;
const VIRTGPU_RESOURCE_INFO: u32 = 0xc0106445;
const VIRTGPU_EXECBUFFER: u32 = 0xc0406442;
const VIRTGPU_EXECBUFFER_V1: u32 = 0xc0286442;

const VENUS: u32 = 4;
const MAX_COMMAND: usize = 1 << 20;

pub(crate) struct RenderFile {
    renderer: Arc<dyn Renderer>,
    context: RefCell<Option<Arc<dyn Context>>>,
    initializing: Cell<bool>,
    rings: Cell<u32>,
    next: Cell<u32>,
    buffers: RefCell<BTreeMap<u32, Arc<dyn Mapping>>>,
}

pub(super) fn open(cx: &Cx<'_>) -> Result<Rc<RenderFile>, Errno> {
    Ok(Rc::new(RenderFile {
        renderer: cx.kr().gpu.clone().ok_or(Errno::ENXIO)?,
        context: RefCell::new(None),
        initializing: Cell::new(false),
        rings: Cell::new(0),
        next: Cell::new(1),
        buffers: RefCell::new(BTreeMap::new()),
    }))
}

impl RenderFile {
    fn context(&self) -> Result<Arc<dyn Context>, Errno> {
        self.context.borrow().clone().ok_or(Errno::EINVAL)
    }

    pub(crate) fn mapping(&self, offset: u64, len: u64) -> Result<Arc<dyn Mapping>, Errno> {
        // Each handle has a distinct 4 GiB mmap-offset range. Blob sizes fit in a u32.
        if offset as u32 != 0 {
            return Err(Errno::EINVAL);
        }
        self.buffers
            .borrow()
            .get(&((offset >> 32) as u32))
            .filter(|b| len <= b.size() as u64)
            .cloned()
            .ok_or(Errno::EINVAL)
    }
}

fn u32_at(bytes: &[u8], i: usize) -> u32 {
    u32::from_le_bytes(bytes[i..i + 4].try_into().unwrap())
}
fn u64_at(bytes: &[u8], i: usize) -> u64 {
    u64::from_le_bytes(bytes[i..i + 8].try_into().unwrap())
}

fn version(cx: &Cx<'_>, arg: u64) -> SysResult {
    let mut v: [u8; 64] = get(cx, arg)?;
    v[..12].fill(0);
    v[4..8].copy_from_slice(&1u32.to_le_bytes());
    for (i, text) in [(16, &b"virtio_gpu"[..]), (32, b"0"), (48, b"Virtio GPU")] {
        let len = u64_at(&v, i).min(text.len() as u64) as usize;
        let dest = u64_at(&v, i + 8);
        if dest != 0 && len != 0 {
            cx.write_user(UserSlice::new(dest, len), &text[..len])?;
        }
        v[i..i + 8].copy_from_slice(&(text.len() as u64).to_le_bytes());
    }
    put(cx, arg, v)?;
    Ok(0)
}

fn init(cx: &mut Cx<'_>, file: &RenderFile, arg: u64) -> SysResult {
    if file.initializing.get() || file.context.borrow().is_some() {
        return Err(Errno::EBUSY);
    }
    let req: [u8; 16] = get(cx, arg)?;
    let count = u32_at(&req, 0);
    if count > 3 || u32_at(&req, 4) != 0 {
        return Err(Errno::EINVAL);
    }
    let mut capset = false;
    let mut rings = 1;
    let mut seen = 0;
    for i in 0..count {
        let ptr = u64_at(&req, 8)
            .checked_add(16 * i as u64)
            .ok_or(Errno::EFAULT)?;
        let param: [u8; 16] = get(cx, ptr)?;
        let (key, val) = (u64_at(&param, 0), u64_at(&param, 8));
        match (key, val) {
            (1, 4) => capset = true,
            (2, 1..=64) => rings = val as u32,
            (3, 0) => (),
            _ => return Err(Errno::EINVAL),
        }
        if seen & (1 << key) != 0 {
            return Err(Errno::EINVAL);
        }
        seen |= 1 << key;
    }
    if !capset {
        return Err(Errno::EINVAL);
    }
    let renderer = file.renderer.clone();
    file.initializing.set(true);
    let result = cx.unlocked(move || renderer.open());
    file.initializing.set(false);
    *file.context.borrow_mut() = Some(result?);
    file.rings.set(rings);
    Ok(0)
}

fn create(cx: &mut Cx<'_>, file: &RenderFile, arg: u64) -> SysResult {
    let mut req: [u8; 48] = get(cx, arg)?;
    let size = u64_at(&req, 16);
    let blob = u64_at(&req, 40);
    if u32_at(&req, 0) != 2
        || u32_at(&req, 4) != 1
        || size == 0
        || size > u32::MAX as u64
        || size & 4095 != 0
        || u64_at(&req, 24) != 0
        || u64_at(&req, 32) != 0
    {
        return Err(Errno::EINVAL);
    }
    let ctx = file.context()?;
    let id = file.next.get();
    file.next.set(id.checked_add(1).ok_or(Errno::ENOSPC)?);
    let mapped = cx.unlocked(|| ctx.create(id, blob, size))?;
    req[8..12].copy_from_slice(&id.to_le_bytes());
    req[12..16].copy_from_slice(&id.to_le_bytes());
    super::copy_result(cx, |cx| put(cx, arg, req))?;
    file.buffers.borrow_mut().insert(id, mapped);
    Ok(0)
}

fn submit(cx: &mut Cx<'_>, file: &RenderFile, arg: u64, size: usize) -> SysResult {
    let mut req = [0u8; 64];
    cx.read_user(UserSlice::new(arg, size), &mut req[..size])?;
    let flags = u32_at(&req, 0);
    let len = u32_at(&req, 4) as usize;
    let handles = u32_at(&req, 24) as usize;
    let ring = if flags & 4 != 0 { u32_at(&req, 32) } else { 0 };
    if flags & !6 != 0
        || ring >= file.rings.get()
        || len > MAX_COMMAND
        || !len.is_multiple_of(4)
        || handles > 16384
        || u64_at(&req, 40) != 0
    {
        return Err(Errno::EINVAL);
    }
    let mut command = vec![0; len];
    if len != 0 {
        cx.read_user(UserSlice::new(u64_at(&req, 8), len), &mut command)?;
    }
    let mut ids = vec![0; handles * 4];
    if handles != 0 {
        cx.read_user(UserSlice::new(u64_at(&req, 16), ids.len()), &mut ids)?;
    }
    let buffers = ids
        .chunks_exact(4)
        .map(|id| {
            file.buffers
                .borrow()
                .get(&u32_at(id, 0))
                .cloned()
                .ok_or(Errno::ENOENT)
        })
        .collect::<Result<Vec<_>, _>>()?;
    let ctx = file.context()?;
    let fence = cx.unlocked(|| ctx.submit(ring, &command, flags & 2 != 0, buffers))?;
    if let Some(fence) = fence {
        let f = OpenFile::new(FileKind::GpuFence(fence), oflags::O_RDONLY);
        let fd = cx.install_fd(f, true)?;
        let out_addr = arg.checked_add(28).ok_or(Errno::EFAULT)?;
        if let Err(e) = super::copy_result(cx, |cx| put(cx, out_addr, fd.to_le_bytes())) {
            cx.fds_mut().close(fd)?;
            return Err(e);
        }
    }
    Ok(0)
}

pub(super) fn ioctl(cx: &mut Cx<'_>, file: &RenderFile, cmd: u32, arg: u64) -> SysResult {
    match cmd {
        DRM_VERSION => version(cx, arg),
        // DRM_IOCTL_GET_CAP: PRIME import/export and kernel syncobjs are unavailable.
        DRM_GET_CAP => {
            let req: [u8; 16] = get(cx, arg)?;
            match u64_at(&req, 0) {
                5 | 0x13 | 0x14 => put(cx, arg + 8, 0u64.to_le_bytes())?,
                _ => return Err(Errno::EINVAL),
            }
            Ok(0)
        }
        VIRTGPU_GETPARAM => {
            let req: [u8; 16] = get(cx, arg)?;
            let value: u32 = match u64_at(&req, 0) {
                1..=4 | 6 => 1,
                5 | 8 | 9 => 0,
                7 => 1 << VENUS,
                _ => return Err(Errno::EINVAL),
            };
            put(cx, u64_at(&req, 8), value.to_le_bytes())?;
            Ok(0)
        }
        VIRTGPU_GET_CAPS => {
            let req: [u8; 24] = get(cx, arg)?;
            if u32_at(&req, 0) != VENUS || u32_at(&req, 4) != 0 {
                return Err(Errno::EINVAL);
            }
            let caps = file.renderer.capset();
            let len = caps.len().min(u32_at(&req, 16) as usize);
            cx.write_user(UserSlice::new(u64_at(&req, 8), len), &caps[..len])?;
            Ok(0)
        }
        VIRTGPU_CONTEXT_INIT => init(cx, file, arg),
        VIRTGPU_RESOURCE_CREATE_BLOB => create(cx, file, arg),
        VIRTGPU_MAP | VIRTGPU_RESOURCE_INFO => {
            let mut req: [u8; 16] = get(cx, arg)?;
            let id = u32_at(&req, if cmd == VIRTGPU_MAP { 8 } else { 0 });
            let buffers = file.buffers.borrow();
            let mapping = buffers.get(&id).ok_or(Errno::ENOENT)?;
            if cmd == VIRTGPU_MAP {
                req[..8].copy_from_slice(&((id as u64) << 32).to_le_bytes());
            } else {
                req[4..8].copy_from_slice(&id.to_le_bytes());
                req[8..12].copy_from_slice(&(mapping.size() as u32).to_le_bytes());
                req[12..].copy_from_slice(&2u32.to_le_bytes());
            }
            drop(buffers);
            put(cx, arg, req)?;
            Ok(0)
        }
        VIRTGPU_EXECBUFFER | VIRTGPU_EXECBUFFER_V1 => {
            submit(cx, file, arg, ((cmd >> 16) & 0xff) as usize)
        }
        DRM_GEM_CLOSE => {
            let req: [u8; 8] = get(cx, arg)?;
            let id = u32_at(&req, 0);
            file.buffers.borrow_mut().remove(&id).ok_or(Errno::ENOENT)?;
            Ok(0)
        }
        _ => {
            crate::stub::ioctl(cx, cmd, "virtio_gpu");
            Err(Errno::ENOTTY)
        }
    }
}
