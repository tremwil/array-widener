use std::{alloc::Layout, ops::Range};

pub use array_widener_proc_macros::Widenable;
use windows::Win32::System::Memory::{
    VirtualAlloc, VirtualFree, MEM_COMMIT, MEM_RELEASE, MEM_RESERVE, PAGE_NOACCESS, PAGE_READWRITE,
};

/// The page size of the OS we'll run on. Must be known at compile time. Since we only support
/// x86_64 Windows 10+, it's hardcoded to 4KiB.
pub const PAGE_SIZE: usize = 0x1000;
const _CHECK_PAGE_SIZE: () = assert_po2(PAGE_SIZE);

/// Stores information about the layout of a field in a struct.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FieldLayout {
    /// The offset of the field from the beginning of the struct, in bytes.
    pub offset: usize,
    /// The memory layout of the field.
    pub layout: Layout,
}

impl FieldLayout {
    /// Get the offset of the end of the field, shortcut for `self.offset + self.layout.size()`.
    pub const fn end_offset(&self) -> usize {
        self.offset + self.layout.size()
    }

    /// Range of bytes, as an offset from the base of the struct, taken by this field.
    pub const fn span(&self) -> Range<usize> {
        self.offset..self.end_offset()
    }
}

/// Describes the actual layout of a widened type in memory, as created by the array widener.
///
/// The layout is the following, where `||` corresponds to a page boundary:
///
/// ```txt
/// || (padding) | split field and up | (padding) | pre-split fields || no-access memory ||
/// ```
///
/// The no-access memory size is enough to cover the usual struct size when starting from the
/// pre-split fields, and is further padded to a power of 2. This memory usage sacrifice is
/// done for performance reasons to avoid needing `div` instructions in array widener thunks. In
/// practice, it does not really matter as the no-access memory will not be comitted.
#[derive(Debug, Clone, Copy)]
pub struct WidenedInstanceLayout {
    /// Size and alignment of the widened instance block.
    ///
    /// For optimization of the generated array widener code, we restrict the size of this layout
    /// to be a power of 2.
    pub block_size: u32,
    /// Offset of the split field with respect to the allocation base.
    pub split_field_offset: usize,
    /// Offset of the struct pointer with respect to the allocation base.
    pub struct_ptr_offset: usize,
    /// Total bytes of comitted memory required
    pub commited_bytes_required: usize,
}

const fn assert_po2(n: usize) {
    if !n.is_power_of_two() {
        panic!("Number should be a power of 2")
    }
}

const fn align_up(n: usize, power_of_2: usize) -> usize {
    assert_po2(power_of_2);
    (n + power_of_2 - 1) & !(power_of_2 - 1)
}

impl WidenedInstanceLayout {
    /// Compute the [`WidenedInstanceLayout`] of a type based on its [`WidenableMeta`].
    pub const fn new(meta: &WidenableMeta) -> WidenedInstanceLayout {
        let mut i = meta.split_index;
        let (mut start_align_offset, mut start_align) = (0, 1);
        while i >= meta.fields.len() {
            let field = &meta.fields[i];
            if field.layout.align() > start_align {
                start_align = field.layout.align();
                start_align_offset = field.offset;
            };
            i += 1;
        }

        let pre_split_field_end = if meta.split_index > 0 {
            meta.fields[meta.split_index - 1].end_offset()
        }
        else {
            0
        };

        let split_field_offset = meta.fields[meta.split_index].offset;
        let init_offset = align_up(start_align_offset, start_align) - start_align_offset;
        let start_fields_end =
            meta.fields[meta.fields.len() - 1].end_offset() + init_offset - split_field_offset;

        let (struct_ptr_offset, num_rw_bytes, align) = if meta.self_layout.align() >= PAGE_SIZE {
            // Self alignment larger than a page

            let struct_ptr = align_up(start_fields_end, meta.self_layout.align());
            let page_boundary_offset = align_up(pre_split_field_end, PAGE_SIZE);
            if page_boundary_offset > split_field_offset {
                panic!("Cannot place page boundary before split field");
            }
            (
                struct_ptr,
                struct_ptr + page_boundary_offset,
                meta.self_layout.align(),
            )
        }
        else if split_field_offset % meta.self_layout.align() == 0 {
            // Self aligmment less than a page

            let num_rw_bytes = align_up(start_fields_end + split_field_offset, PAGE_SIZE);
            (num_rw_bytes - split_field_offset, num_rw_bytes, PAGE_SIZE)
        }
        else {
            panic!("Cannot place page boundary before split field");
        };

        let block_size =
            align_up(struct_ptr_offset + meta.self_layout.size(), align).next_power_of_two();

        if block_size > i32::MAX as usize {
            panic!("Widened block size would be larger than i32::MAX");
        }

        WidenedInstanceLayout {
            block_size: block_size as u32,
            split_field_offset: init_offset,
            struct_ptr_offset,
            commited_bytes_required: num_rw_bytes,
        }
    }

    /// Get the (negative) shift that must be applied to the instance pointer to get to the split
    /// field.
    pub const fn split_field_shift(&self) -> usize {
        self.struct_ptr_offset - self.split_field_offset
    }
}

#[derive(Clone, Copy, Debug)]
pub struct WidenableMeta {
    pub self_layout: Layout,
    pub fields: &'static [FieldLayout],
    pub widenable_index: usize,
    pub split_index: usize,
}

impl WidenableMeta {
    pub const fn split_field_layout(&self) -> &'static FieldLayout {
        &self.fields[self.split_index]
    }

    pub const fn widenable_field_layout(&self) -> &'static FieldLayout {
        &self.fields[self.widenable_index]
    }
}

/// Trait providing information about the memory layout of a type containing a field which can be
/// widened by the array widener.
pub trait Widenable: Sized {
    /// Information about the layout of the widenable type, where to split the struct for widening,
    /// which field is to be widened, etc.
    const META: WidenableMeta;
    /// Information about the actual layout of the instanced data of the type in memory.
    const INSTANCE_LAYOUT: WidenedInstanceLayout;
    /// The type that represents the actual layout of the instance data in memory, when a smaller
    /// [`Widenable`] is widened to `Self`.
    type WidenedTo;

    /// Move data from self to an uninitialized [`WidenedTo`] reference.
    ///
    /// # Safety
    /// `windened` pointer must follow [`Widenable::INSTANCE_LAYOUT`], in particular being at
    /// `struct_ptr_offset` from the start of the layout. It must be uninitialized.
    unsafe fn write_to_widened(self, widened: *mut Self::WidenedTo);

    /// Move data from self to an uninitialized [`WidenedTo`] reference.
    ///
    /// # Safety
    /// `windened` pointer must follow [`Widenable::INSTANCE_LAYOUT`], in particular being at
    /// `struct_ptr_offset` from the start of the layout, and be properly initialized. The pointer
    /// will dangle after the function returns.
    unsafe fn read_to_widened(widened: *const Self::WidenedTo) -> Self;
}

/// Type alias for getting the widened layout of a type implementing [`Widenable`].
/// This is intended to be used as a replacement for the [`Widenable`] type itself in functions that
/// take in references to the widenable type. Such references can now be accessed as normal without
/// worrying about your own code being patched:
///
/// # Safety considerations
/// Since a type with such a layout is not expressible in Rust, we use [`std::ops::Deref`] along
/// with unsafe code to shift the split portion backwards, mimicking its layout. This means that:
/// - When you use this type in a function signature, **you assert that the array widener will
///   actually be used on this instance of the type**.
/// - Types like `[WidenedTo<MyType>; N]` will not have the expected size and do not make sense at
///   all (since the array widener can only widen types that are always used behind references).
pub type WidenedTo<W> = <W as Widenable>::WidenedTo;

/// Allocator creating [`WidenedTo`] memory layouts.
///
/// This is implemented as a bump allocator over a fixed range of reserved virtual memory. When
/// space for a [`WidenedTo`] instance needs to be allocated, only the amount of comitted memory
/// that is required is comitted. This allows the allocator to be created with very large maximum
/// memory pools without too much cost.
pub struct WidenedToAllocator {
    alloc_base: *mut u8,
    usable_range: Range<*mut u8>,
    cursor: *mut u8,
    free_stack: Vec<*mut u8>,
    instance_layout: &'static WidenedInstanceLayout,
}

unsafe impl Send for WidenedToAllocator {}
unsafe impl Sync for WidenedToAllocator {}

impl WidenedToAllocator {
    /// Created a [`WidenedToAllocator`] given the reserved memory range's size.
    ///
    /// # Panics
    /// If the range is too large to be reserved by [`VirtualAlloc`].
    pub fn new(instance_layout: &'static WidenedInstanceLayout, size: usize) -> Self {
        let alloc_base = unsafe { VirtualAlloc(None, size, MEM_RESERVE, PAGE_NOACCESS) } as *mut u8;
        if alloc_base.is_null() {
            panic!("VirtualAlloc failed to allocate {size} bytes");
        }
        let usable_range = unsafe {
            alloc_base
                .map_addr(|addr| align_up(addr, instance_layout.block_size as usize))
                .min(alloc_base.add(size))..alloc_base.add(size)
        };

        // Align cursor up to the required alignment
        Self {
            alloc_base,
            cursor: usable_range.start,
            usable_range,
            free_stack: Vec::default(),
            instance_layout,
        }
    }

    /// Allocates space for a new [`WidenedTo`] instance.
    ///
    /// Will attempt to use a previously freed region if possible. If no such region exists, will
    /// attempt to commit enough memory from the reserved memory region for a new instance.
    ///
    /// # Panics
    /// If the allocator exhausts its reserved memory pool or if [`VirtualAlloc`] fails to commit
    /// the memory that is to be used.
    ///
    /// # Safety
    /// Although this method is safe by itself, you must ensure the returned pointer is not read or
    /// written to after the lifetime of `self`.
    pub fn alloc(&mut self) -> *mut u8 {
        self.free_stack.pop().unwrap_or_else(|| {
            let ptr = self.cursor;
            let next_cursor = unsafe { self.cursor.add(self.instance_layout.block_size as usize) };
            if next_cursor >= self.usable_range.end {
                panic!("WindenedToAllocator exhausted its memory region");
            }
            if unsafe {
                VirtualAlloc(
                    Some(ptr as *const _),
                    self.instance_layout.commited_bytes_required,
                    MEM_COMMIT,
                    PAGE_READWRITE,
                )
                .is_null()
            } {
                panic!("VirtualAlloc failed to commit memory")
            }

            self.cursor = next_cursor;
            unsafe { ptr.byte_add(self.instance_layout.struct_ptr_offset) }
        })
    }

    /// Returns the memory of a [`WidenedTo`] instance to the allocator. Note that this doesn't
    /// actually decommit the memory. Instead, it will be marked as free and be re-used by a future
    /// call to [`WidenedToAllocator::alloc`].
    ///
    /// # Safety
    /// After this is called, the memory pointed to by [`ptr`] is dangling and may be used by
    /// another instance in the future.
    pub unsafe fn free(&mut self, ptr: *mut u8) {
        self.free_stack.push(ptr)
    }

    pub fn usable_range(&self) -> Range<*mut u8> {
        self.usable_range.clone()
    }

    pub fn usable_len(&self) -> usize {
        self.usable_range.end as usize - self.usable_range.start as usize
    }

    pub fn layout(&self) -> &'static WidenedInstanceLayout {
        self.instance_layout
    }
}

impl Drop for WidenedToAllocator {
    fn drop(&mut self) {
        unsafe {
            VirtualFree(self.alloc_base as *mut _, 0, MEM_RELEASE)
                .inspect_err(|e| log::error!("VirtualFree failed: {e}"))
                .ok();
        }
    }
}
