use std::{
    alloc::Layout,
    collections::hash_map::Entry,
    ffi::c_void,
    ops::{Deref, DerefMut, Range},
    ptr::NonNull,
    sync::{
        atomic::{AtomicPtr, Ordering::Relaxed},
        LazyLock,
    },
};

use fxhash::FxHashMap;
use windows::Win32::{
    Foundation::{GetLastError, HANDLE, HMODULE},
    System::{
        Memory::{
            VirtualAlloc, VirtualAlloc2, VirtualFree, VirtualQuery, MEMORY_BASIC_INFORMATION,
            MEM_ADDRESS_REQUIREMENTS, MEM_COMMIT, MEM_EXTENDED_PARAMETER, MEM_EXTENDED_PARAMETER_0,
            MEM_EXTENDED_PARAMETER_1, MEM_RELEASE, MEM_RESERVE, PAGE_EXECUTE_READWRITE,
            PAGE_READWRITE,
        },
        SystemInformation::{GetSystemInfo, SYSTEM_INFO},
        Threading::GetCurrentProcess,
    },
};

use crate::{
    arena::{self, Arena, ArenaAllocAt, ExecArena},
    winapi_utils::{hmodule_from_ptr, module_region},
};

const NEAR_JMP_RANGE: usize = i32::MAX as usize;

/// Owned buffer of memory with read/write/execute permissions.
///
/// Can [`DerefMut`] into a regular [`u8`] slice, but does not directly contain a mutable reference
/// to the buffer's memory. As such, it may be safely used as storage for an allocator or other
/// types that lend memory.
#[derive(Debug)]
pub struct RWEBuffer {
    alloc_base: NonNull<c_void>,
    len: usize,
}

unsafe impl Send for RWEBuffer {}
unsafe impl Sync for RWEBuffer {}

impl Drop for RWEBuffer {
    fn drop(&mut self) {
        unsafe { VirtualFree(self.alloc_base.as_ptr(), 0, MEM_RELEASE) }
            .inspect_err(|e| log::error!("VirtualFree failed: {e}"))
            .ok();
    }
}

impl AsRef<[u8]> for RWEBuffer {
    fn as_ref(&self) -> &[u8] {
        unsafe { std::slice::from_raw_parts(self.alloc_base.as_ptr() as *const u8, self.len) }
    }
}

impl AsMut<[u8]> for RWEBuffer {
    fn as_mut(&mut self) -> &mut [u8] {
        unsafe { std::slice::from_raw_parts_mut(self.alloc_base.as_ptr() as *mut u8, self.len) }
    }
}

impl Deref for RWEBuffer {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        self.as_ref()
    }
}

impl DerefMut for RWEBuffer {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.as_mut()
    }
}

impl RWEBuffer {
    /// Creates a buffer of RWE memory with the given size.
    ///
    /// Internally, uses the [`VirtualAlloc`] function.
    ///
    /// # Panics
    /// If the allocation fails.
    pub fn new(size: usize) -> Self {
        let alloc_base =
            unsafe { VirtualAlloc(None, size, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE) };

        Self {
            alloc_base: NonNull::new(alloc_base).unwrap_or_else(|| {
                panic!("VirtualAlloc failed (last error = {:?})", unsafe {
                    GetLastError()
                })
            }),
            len: size,
        }
    }

    /// Tries to allocate a buffer of RWE memory such that every byte in `region` is within
    /// near jump range (2^31 - 1 bytes) from every byte in the RWE buffer.
    ///
    /// If no such region can be found by the operating system, returns [`None`].
    pub fn new_near_region(size: usize, region: &Range<usize>) -> Option<Self> {
        static ALLOC_GRANULARITY: LazyLock<usize> = LazyLock::new(|| {
            let mut sysinfo = SYSTEM_INFO::default();
            unsafe {
                GetSystemInfo(&mut sysinfo as *mut _);
            }
            sysinfo.dwAllocationGranularity as usize
        });
        let alloc_granularity = *ALLOC_GRANULARITY;

        let address_requirements = MEM_ADDRESS_REQUIREMENTS {
            LowestStartingAddress: {
                let minimum_unaligned = region.end.saturating_sub(NEAR_JMP_RANGE);
                (minimum_unaligned + alloc_granularity - 1) & !(alloc_granularity - 1)
            } as *mut c_void,
            HighestEndingAddress: {
                let highest_unaligned = region.start.checked_add(NEAR_JMP_RANGE)?;
                let highest_aligned =
                    (highest_unaligned & !(alloc_granularity - 1)).saturating_sub(1);
                highest_aligned.min((1 << 47) - 1) as *mut c_void
            },
            Alignment: 0,
        };

        let mut extended_params = [MEM_EXTENDED_PARAMETER {
            Anonymous1: MEM_EXTENDED_PARAMETER_0 { _bitfield: 1 },
            Anonymous2: MEM_EXTENDED_PARAMETER_1 {
                Pointer: &address_requirements as *const _ as *mut c_void,
            },
        }];

        let alloc_base = unsafe {
            VirtualAlloc2(
                HANDLE(0 as *mut c_void),
                None,
                size,
                MEM_RESERVE | MEM_COMMIT,
                PAGE_EXECUTE_READWRITE.0,
                Some(&mut extended_params),
            )
        };

        Some(Self {
            alloc_base: NonNull::new(alloc_base)?,
            len: size,
        })
    }

    /// Get a pointer to the base of the allocated memory region.
    pub fn alloc_base(&self) -> NonNull<c_void> {
        self.alloc_base
    }

    /// Get the size of the allocated memory region.
    pub fn len(&self) -> usize {
        self.len
    }

    /// Get the allocated memory region's start and end address as a range.
    pub fn region(&self) -> Range<usize> {
        let buf_start = self.alloc_base.as_ptr() as usize;
        buf_start..buf_start + self.len()
    }
}

/// Thread-safe arena based on a bump allocator backed by a RWE memory buffer.
pub struct RWEArena {
    buffer: RWEBuffer,
    cursor: AtomicPtr<c_void>,
}

impl RWEArena {
    /// Create a new [`RWEArena`] backed by a memory buffer of `size` bytes.
    pub fn new(size: usize) -> Self {
        RWEBuffer::new(size).into()
    }

    /// Attempt a new [`RWEArena`] backed by a memory buffer of `size` bytes, which is allocated
    /// such that every byte is within near jump range (+- 2^31 - 1) of `region`.
    pub fn new_near_region(size: usize, region: &Range<usize>) -> Option<Self> {
        Some(RWEBuffer::new_near_region(size, region)?.into())
    }

    /// Amount of bytes of the buffer that have been consumed by the allocator.
    ///
    /// Read with [`Relaxed`] memory ordering emantics.
    pub fn bytes_consumed(&self) -> usize {
        unsafe { self.cursor.load(Relaxed).offset_from(self.buffer.alloc_base().as_ptr()) as usize }
    }

    /// Amount of bytes of the buffer that have not been consumed yet.
    ///
    /// Read with [`Relaxed`] memory ordering semantics.
    pub fn bytes_remaining(&self) -> usize {
        unsafe {
            self.buffer
                .alloc_base()
                .as_ptr()
                .byte_add(self.buffer.len())
                .offset_from(self.cursor.load(Relaxed)) as usize
        }
    }

    /// Access the internal buffer backing the allocator.
    ///
    /// # Safety
    /// Since the memory of the [`RWEBuffer`] can be accessed as a u8 slice without `unsafe`, you
    /// must be careful to **not** do so, as the slice with alias with references to allocated data,
    /// which is *always* UB.
    pub unsafe fn buffer(&self) -> &RWEBuffer {
        &self.buffer
    }

    /// Mutably access the internal buffer backing the allocator.
    ///
    /// # Safety
    /// Since the memory of the [`RWEBuffer`] can be accessed as a u8 slice without `unsafe`, you
    /// must be careful to **not** do so, as the slice with alias with references to allocated data,
    /// which is *always* UB.
    pub unsafe fn buffer_mut(&mut self) -> &mut RWEBuffer {
        &mut self.buffer
    }
}

impl From<RWEBuffer> for RWEArena {
    fn from(value: RWEBuffer) -> Self {
        Self {
            cursor: AtomicPtr::new(value.alloc_base().as_ptr()),
            buffer: value,
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum RWEArenaError {
    #[error("Out of memory")]
    OutOfMemory(#[from] arena::OutOfMemoryError),
    #[error("Address is already part of an allocated range")]
    AddressNotAvailable,
}

impl Arena for RWEArena {
    type Error = RWEArenaError;

    fn alloc(&self, layout: Layout) -> Result<*mut (), Self::Error> {
        let buffer_end = self.buffer.alloc_base().as_ptr() as usize + self.buffer.len();

        let mut aligned_cursor: usize = 0;
        self.cursor
            .fetch_update(Relaxed, Relaxed, |cursor| {
                let cursor = cursor as usize;

                // Handle integer overflow correctly
                aligned_cursor = cursor.wrapping_add(layout.align() - 1) & !(layout.align() - 1);
                let next_cursor = (aligned_cursor >= cursor)
                    .then_some(aligned_cursor)?
                    .checked_add(layout.size())?;

                (next_cursor <= buffer_end).then_some(next_cursor as *mut c_void)
            })
            .or(Err(arena::OutOfMemoryError))?;

        Ok(aligned_cursor as *mut ())
    }
}

// SAFETY: RWEArena allocates executable memory
unsafe impl ExecArena for RWEArena {}

impl ArenaAllocAt for RWEArena {
    fn avail_buffer(&self) -> *mut [u8] {
        let cursor = self.cursor.load(Relaxed) as *mut u8;
        let buffer_end = self.buffer.alloc_base().as_ptr() as usize + self.buffer.len();
        std::ptr::slice_from_raw_parts_mut(cursor, buffer_end - cursor as usize)
    }

    fn alloc_at(&self, desired_address: usize, size: usize) -> Result<*mut [u8], Self::Error> {
        let buffer_end = self.buffer.alloc_base().as_ptr() as usize + self.buffer.len();
        let region_end = desired_address.checked_add(size).ok_or(arena::OutOfMemoryError)?;
        if region_end > buffer_end {
            return Err(arena::OutOfMemoryError.into());
        }

        self.cursor
            .fetch_update(Relaxed, Relaxed, |cursor| {
                (cursor as usize <= desired_address).then_some(region_end as *mut c_void)
            })
            .or(Err(arena::OutOfMemoryError))?;

        Ok(std::ptr::slice_from_raw_parts_mut(
            desired_address as *mut _,
            size,
        ))
    }
}

/// Creates [`RWEArena`] instances within near jump range to memory regions and caches them for
/// future use.
///
/// The arenas are indexed by hmodule. The reasoning for this is to ensure we always pick the same
/// arena when getting one based on an hmodule.
pub struct RWEArenaCache {
    mod_arenas: FxHashMap<u64, Box<RWEArena>>,
    non_mod_arenas: Vec<Box<RWEArena>>,
    arena_size: usize,
}

impl RWEArenaCache {
    /// Create a [`RWEArenaCache`] given the size of created arenas.
    pub fn new(arena_size: usize) -> Self {
        Self {
            mod_arenas: Default::default(),
            non_mod_arenas: Default::default(),
            arena_size,
        }
    }

    fn find_near_arena<'a>(
        region: &Range<usize>,
        arenas: impl IntoIterator<Item = &'a mut Box<RWEArena>>,
    ) -> Option<&'a mut Box<RWEArena>> {
        // Find the maximum separation between two ranges
        fn max_sep(a: &Range<usize>, b: &Range<usize>) -> usize {
            return Ord::max(a.end, b.end) - Ord::min(a.start, b.start);
        }
        arenas
            .into_iter()
            .filter_map(|ar| (max_sep(&ar.buffer.region(), &region) < NEAR_JMP_RANGE).then_some(ar))
            .max_by_key(|ar| {
                let arena_region = ar.buffer.region();
                if arena_region.start <= region.start && arena_region.end >= region.end {
                    return usize::MAX;
                }
                ar.bytes_remaining()
            })
    }

    pub fn anywhere<'a>(&'a mut self, size: usize) -> &'a mut RWEArena {
        if self.non_mod_arenas.is_empty() {
            self.non_mod_arenas.push(Box::new(RWEArena::new(size)));
        }

        // SAFETY:
        // - Lifetime can be extended to self as arenas are never freed until drop
        // - Reference is the vector is stable as the arena is boxed
        unsafe { &mut *(self.non_mod_arenas.last_mut().unwrap().as_mut() as *mut _) }
    }

    /// Tries to get an arena within near jump range of a given memory region.
    ///
    /// Will first check if any existing arena works. Otherwise, attempts to create a new one.
    pub fn near_region<'a>(&'a mut self, region: &Range<usize>) -> Option<&'a mut RWEArena> {
        let all_arenas = self.mod_arenas.values_mut().chain(self.non_mod_arenas.iter_mut());
        if let Some(arena) = Self::find_near_arena(region, all_arenas) {
            // SAFETY:
            // - Lifetime can be extended to self as arenas are never freed until drop
            // - Reference is the vector is stable as the arena is boxed
            return Some(unsafe { &mut *(arena.as_mut() as *mut _) });
        }

        self.non_mod_arenas.push(Box::new(RWEArena::new_near_region(
            self.arena_size,
            region,
        )?));
        // SAFETY:
        // - Lifetime can be extended to self as arenas are never freed until drop
        // - Reference is the vector is stable as the arena is boxed
        Some(unsafe { &mut *(self.non_mod_arenas.last_mut().unwrap().as_mut() as *mut _) })
    }

    /// Tries to get an arena within near jump range of a given module.
    ///
    /// If no arena was created for this module specifically, will attempt to create a new one.
    pub fn near_module<'a>(&'a mut self, module: HMODULE) -> Option<&'a mut RWEArena> {
        let boxed = match self.mod_arenas.entry(module.0 as u64) {
            Entry::Occupied(b) => b.into_mut(),
            Entry::Vacant(vacant) => {
                let arena = Box::new(RWEArena::new_near_region(
                    self.arena_size,
                    &module_region(module),
                )?);
                vacant.insert(arena)
            }
        };
        Some(unsafe { &mut *(boxed.as_mut() as *mut _) })
    }

    /// Tries to get an arena within near jump range of the module or memory region a pointer is in.
    ///
    /// If the pointer lies inside a module, the region is the entire module. Otherwise, it is the
    /// range of pages from the allocation base to the end of the region returned by VirtualQuery.
    pub fn near_ptr<'a>(&'a mut self, ptr: *const ()) -> Option<&'a mut RWEArena> {
        if let Some(hmod) = hmodule_from_ptr(ptr) {
            return self.near_module(hmod);
        }

        let mut mbi = MEMORY_BASIC_INFORMATION::default();
        if unsafe {
            VirtualQuery(
                Some(ptr as *const _),
                &mut mbi as *mut _,
                std::mem::size_of_val(&mbi),
            ) != 0
                && mbi.State == MEM_COMMIT
        } {
            let start = mbi.AllocationBase as usize;
            let end = mbi.BaseAddress as usize + mbi.RegionSize;
            self.near_region(&(start..end))
        }
        else {
            None
        }
    }
}

mod tests {
    use windows::Win32::Foundation::GetLastError;

    use super::RWEArenaCache;

    #[test]
    fn test_near_ptr() {
        let mut arena_cache = RWEArenaCache::new(0x10000);
        if arena_cache.near_ptr(test_near_ptr as *const ()).is_none() {
            panic!("{}", unsafe { GetLastError() }.to_hresult().message())
        }
    }
}
