use std::{
    alloc::Layout,
    borrow::{Borrow, BorrowMut},
    fmt::{Debug, Display},
    marker::PhantomData,
    mem::{ManuallyDrop, MaybeUninit},
    ops::{Deref, DerefMut, Range},
    ptr::NonNull,
};

/// Error raised when an arena allocator fails to allocate memory.
#[derive(Clone, Copy, Debug)]
pub struct OutOfMemoryError;
impl Display for OutOfMemoryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        Debug::fmt(&self, f)
    }
}
impl std::error::Error for OutOfMemoryError {}

/// Types that provide arena allocation functionality.
///
/// This trait only contains the core allocation logic of the arena, [`Arena::alloc`], in order to
/// be dyn-compatible. Other convenience methods for moving or copying values into the arena can be
/// found in the [`ArenaExt`] trait.
pub trait Arena {
    type Error: From<OutOfMemoryError>;

    /// Allocate memory corresponding to a given [`Layout`].
    fn alloc(&self, layout: Layout) -> Result<*mut (), Self::Error>;
}

/// Subtrait of [`Arena`] to be implemented by arenas that allocate RWE (read-write-executable)
/// memory.
///
/// # Safety
/// When implementing this trait, you assert that the memory returned by [`Arena::alloc`] is RWE
/// memory.
pub unsafe trait ExecArena: Arena {}

/// Mutable reference to data allocated in an [`Arena`].
///
/// Has ownership semantics, so it will call the destructor of the pointed-to value when dropped. To
/// purposefully leak the reference, use [`ArenaRef::leak`] or [`ArenaRef::into`].
#[repr(transparent)]
pub struct ArenaRef<'a, T: 'a + ?Sized> {
    ptr: NonNull<T>,
    phantom: PhantomData<(&'a mut T, T)>,
}

// SAFETY: &mut T is Send iff T is Send
unsafe impl<'a, T: 'a + ?Sized + Send> Send for ArenaRef<'a, T> {}
// SAFETY: &mut T is Sync iff T is Sync
unsafe impl<'a, T: 'a + ?Sized + Sync> Sync for ArenaRef<'a, T> {}

impl<'a, T: 'a + ?Sized> Drop for ArenaRef<'a, T> {
    fn drop(&mut self) {
        unsafe {
            std::ptr::drop_in_place(self.ptr.as_ptr());
        }
    }
}

impl<'a, T: 'a + Copy> ArenaRef<'a, T> {
    /// Consumes this [`ArenaRef`], returning the underlying mutable reference.
    #[inline(always)]
    pub fn into_mut(self) -> &'a mut T {
        self.leak()
    }
}

impl<'a, T: 'a + Copy> ArenaRef<'a, [T]> {
    /// Consumes this [`ArenaRef`], returning the underlying mutable reference.
    #[inline(always)]
    pub fn into_mut(self) -> &'a mut [T] {
        self.leak()
    }
}

impl<'a, T: 'a + ?Sized> ArenaRef<'a, T> {
    /// Wrap a mutable reference into [`ArenaRef`].
    ///
    /// # SAFETY:
    /// The reference must not be used after `self` is dropped.
    unsafe fn new(value: &'a mut T) -> Self {
        ArenaRef {
            ptr: unsafe { NonNull::new_unchecked(value as *mut _) },
            phantom: PhantomData,
        }
    }

    /// Get a [`NonNull`] pointer to the inner value. You are responsible for respecting Rust
    /// aliasing rules.
    #[inline(always)]
    pub fn as_ptr(&self) -> NonNull<T> {
        self.ptr
    }

    /// Get a mut pointer to the inner value. You are responsible for respecting Rust aliasing
    /// rules.
    #[inline(always)]
    pub fn as_const_ptr(&self) -> *const T {
        self.ptr.as_ptr()
    }

    /// Get a const pointer to the inner value. You are responsible for respecting Rust aliasing
    /// rules.
    #[inline(always)]
    pub fn as_mut_ptr(&self) -> *mut T {
        self.ptr.as_ptr()
    }

    /// Consumes this [`ArenaRef`], returning the underlying mutable reference. This leaks the
    /// value; its [`Drop`] implementation will never be called.
    ///
    /// Prefer [`ArenaRef::into_mut`] for clarity if `T` is [`Copy`] or a slice of [`Copy`] values.
    #[inline(always)]
    pub fn leak(self) -> &'a mut T {
        let mut leaked = ManuallyDrop::new(self).ptr;
        // SAFETY: inner mutable reference is still valid for lifetime 'a
        unsafe { leaked.as_mut() }
    }
}

impl<'a, T: 'a + ?Sized> Deref for ArenaRef<'a, T> {
    type Target = T;

    #[inline(always)]
    fn deref(&self) -> &Self::Target {
        self.as_ref()
    }
}

impl<'a, T: 'a + ?Sized> DerefMut for ArenaRef<'a, T> {
    #[inline(always)]
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.as_mut()
    }
}

impl<'a, T: 'a + ?Sized> AsRef<T> for ArenaRef<'a, T> {
    #[inline(always)]
    fn as_ref(&self) -> &T {
        unsafe { self.ptr.as_ref() }
    }
}

impl<'a, T: 'a + ?Sized> AsMut<T> for ArenaRef<'a, T> {
    #[inline(always)]
    fn as_mut(&mut self) -> &mut T {
        unsafe { self.ptr.as_mut() }
    }
}

impl<'a, T: 'a + ?Sized> Borrow<T> for ArenaRef<'a, T> {
    #[inline(always)]
    fn borrow(&self) -> &T {
        self.as_ref()
    }
}

impl<'a, T: 'a + ?Sized> BorrowMut<T> for ArenaRef<'a, T> {
    #[inline(always)]
    fn borrow_mut(&mut self) -> &mut T {
        self.as_mut()
    }
}

pub struct TryInitError<'a, E, T: 'a> {
    pub error: E,
    pub init: ArenaRef<'a, [T]>,
    pub uninit: ArenaRef<'a, [MaybeUninit<T>]>,
}

pub type TryInitResult<'a, E, T> = Result<ArenaRef<'a, [T]>, TryInitError<'a, E, T>>;

// ArenaRef heplers for `MaybeUninit` slices
impl<'a, T: 'a> ArenaRef<'a, [MaybeUninit<T>]> {
    /// Populate each element of the allocated slice using a function producing values of `T` given
    /// a slice index, returning an [`ArenaRef`] over the populated slice.
    pub fn init(self, mut init_fn: impl FnMut(usize) -> T) -> ArenaRef<'a, [T]> {
        let slice = self.leak();
        for (i, mem) in slice.iter_mut().enumerate() {
            mem.write(init_fn(i));
        }
        unsafe { ArenaRef::new(&mut *(slice as *mut _ as *mut [T])) }
    }

    /// Tries to populate each element of the allocated slice using a faillible function producing
    /// values of `T` given a slice index.
    ///
    /// If all array slots were initialized, returns `Ok` with the populated slice.
    /// Otherwise, returns `Err` with a [`TryInitError`] providing the error along with both the
    /// initialized and uninitialized portions of the slice.
    pub fn try_init<E>(
        self,
        mut init_fn: impl FnMut(usize) -> Result<T, E>,
    ) -> TryInitResult<'a, E, T> {
        let slice = self.leak();

        let result: Result<(), (usize, E)> =
            slice.iter_mut().enumerate().try_for_each(|(i, mem)| {
                mem.write(init_fn(i).map_err(|err| (i, err))?);
                Ok(())
            });

        let num_init = result.as_ref().err().map(|e| e.0).unwrap_or(slice.len());
        let (init, uninit) = slice.split_at_mut(num_init);
        let init = unsafe { ArenaRef::new(&mut *(init as *mut _ as *mut [T])) };
        let uninit = unsafe { ArenaRef::new(uninit) };

        match result {
            Ok(_) => Ok(init),
            Err((_, error)) => Err(TryInitError {
                error,
                init,
                uninit,
            }),
        }
    }
}

impl<'a, T: 'a + Default> ArenaRef<'a, [MaybeUninit<T>]> {
    /// Populate each element of the allocated slice using [`Default::default`].
    pub fn init_default(self) -> ArenaRef<'a, [T]> {
        self.init(|_| Default::default())
    }
}

/// Extension trait for [`Arena`] implementors which provides methods for moving or copying
/// values into an arena.
pub trait ArenaExt: Arena {
    /// Allocates enough space for a slice of `n` elements, and returns a [`MaybeUninit`] slice
    /// corresponding to it.
    fn alloc_slice<'a, T: 'a>(
        &'a self,
        n: usize,
    ) -> Result<ArenaRef<'a, [MaybeUninit<T>]>, Self::Error> {
        let layout = Layout::array::<T>(n).or(Err(OutOfMemoryError))?;
        let ptr = self.alloc(layout)? as *mut MaybeUninit<T>;
        Ok(unsafe { ArenaRef::new(std::slice::from_raw_parts_mut(ptr, n)) })
    }

    /// Allocates a slot into the arena and moves `value` into it.
    #[inline]
    fn store<'a, T: 'a>(&'a self, value: T) -> Result<ArenaRef<'a, T>, Self::Error> {
        let ptr = self.alloc(Layout::new::<T>())? as *mut MaybeUninit<T>;
        Ok(unsafe { ArenaRef::new((*ptr).write(value)) })
    }

    /// Creates an iterator which consumes `values`, creating a separate allocation for each item.
    #[inline]
    fn store_iter<'a, T: 'a>(
        &'a self,
        values: impl IntoIterator<Item = T>,
    ) -> impl Iterator<Item = Result<ArenaRef<'a, T>, Self::Error>> {
        let mut values = values.into_iter();
        std::iter::from_fn(move || Some(self.store(values.next()?)))
    }

    /// Creates an iterator which consumes references to values, cloning them into individual
    /// allocations.
    #[inline]
    fn clone_iter<'a: 'b, 'b, T: 'a + Clone>(
        &'a self,
        values: impl IntoIterator<Item = &'b T>,
    ) -> impl Iterator<Item = Result<ArenaRef<'a, T>, Self::Error>> {
        self.store_iter(values.into_iter().cloned())
    }

    /// Creates a contiguous allocation and writes all items of an [`ExactSizeIterator`] to it.
    ///
    /// Any items produced by the iterator at and past [`ExactSizeIterator::len`] will not be
    /// processed. Similarly, if the iterator ends early, the resulting slice will be shorter than
    /// [`ExactSizeIterator::len`], and the extra allocated memory will be wasted.
    #[inline]
    fn store_exact_iter<'a, T, I>(&'a self, values: I) -> Result<ArenaRef<'a, [T]>, Self::Error>
    where
        T: 'a,
        I: IntoIterator<Item = T>,
        I::IntoIter: ExactSizeIterator,
    {
        let values = values.into_iter();
        let num_values = values.len();

        let array_layout = Layout::array::<T>(num_values).or(Err(OutOfMemoryError))?;
        let ptr = self.alloc(array_layout)? as *mut MaybeUninit<T>;

        let mut n_written = 0;
        for value in values {
            if n_written >= num_values {
                break;
            }
            // SAFETY: ptr is a valid pointer to up num_values items with the layout of T
            unsafe { &mut *ptr.add(n_written) }.write(value);
            n_written += 1;
        }
        // SAFETY: ptr now points to n_written
        Ok(unsafe { ArenaRef::new(std::slice::from_raw_parts_mut(ptr.cast::<T>(), n_written)) })
    }

    /// Creates a contiguous allocation and clones all items of an [`ExactSizeIterator`] to it.
    ///
    /// Any items produced by the iterator at and past [`ExactSizeIterator::len`] will not be
    /// processed. Similarly, if the iterator ends early, the resulting slice will be shorter than
    /// [`ExactSizeIterator::len`], and the extra allocated memory will be wasted.
    #[inline]
    fn clone_exact_iter<'a: 'b, 'b, T, I>(
        &'a self,
        values: I,
    ) -> Result<ArenaRef<'a, [T]>, Self::Error>
    where
        T: 'a + Clone,
        I: IntoIterator<Item = &'b T>,
        I::IntoIter: ExactSizeIterator,
    {
        self.store_exact_iter(values.into_iter().cloned())
    }

    /// Stores a slice of copyable elements in one contiguous allocation efficiently using a single
    /// memcpy.
    ///
    /// This requires the elements to be [`Copy`], implying that they have a no-op destructor. As
    /// such, the resulting reference is not wrapped in [`ArenaRef`].
    ///
    /// If the elements are [`Clone`], use [`ArenaExt::clone_exact_iter`] instead.
    #[inline]
    fn copy_slice<'a, T: 'a + Copy>(
        &'a self,
        slice: &(impl AsRef<[T]> + ?Sized),
    ) -> Result<&'a mut [T], Self::Error> {
        let slice = slice.as_ref();
        let array_layout = Layout::array::<T>(slice.len()).or(Err(OutOfMemoryError))?;
        let ptr = self.alloc(array_layout)? as *mut T;

        unsafe {
            std::ptr::copy_nonoverlapping(slice.as_ptr(), ptr, slice.len());
        }

        Ok(unsafe { std::slice::from_raw_parts_mut(ptr, slice.len()) })
    }
}

impl<A: Arena + ?Sized> ArenaExt for A {}

/// [`Arena`] subtrait which allows peeking available addresses to allocate at, and allocating at a
/// specific address.
pub trait ArenaAllocAt: Arena {
    /// Returns a raw byte slice representing the space available for the next `alloc_at` call.
    ///
    /// In case of a [`Sync`] arena, this range may become unsuitable or already be unsuitable by
    /// the time it is returned.
    fn avail_buffer(&self) -> *mut [u8];

    /// Returns a range of available address space for the next `alloc_at` call.
    ///
    /// In case of a [`Sync`] arena, this range may become unsuitable or already be unsuitable by
    /// the time it is returned.
    fn avail_address_range(&self) -> Range<usize> {
        let buf = self.avail_buffer();
        let start = buf as *mut u8 as usize;
        start..start + buf.len()
    }

    /// Allocates a certain amount of bytes of memory at the given address.
    ///
    /// This takes just a size instead of a full [`Layout`], since the alignment is handled by the
    /// caller.
    fn alloc_at(&self, desired_address: usize, size: usize) -> Result<*mut [u8], Self::Error>;
}

mod tests {
    /// Make sure the drop check prevents use-after-frees when running the destructor of an
    /// allocated value.
    ///
    /// ```compile_fail
    /// use array_widener::arena::{Arena, ArenaExt};
    ///
    /// fn test(arena: impl Arena) {
    ///     let alloc = arena.store(0).unwrap();
    ///     std::mem::drop(arena);
    /// }
    /// ```
    #[allow(dead_code)]
    fn test_drop_check() {}

    /// Make sure that a leaked value ref can't be used after the drop either.
    ///
    /// ```compile_fail
    /// use array_widener::arena::{Arena, ArenaExt};
    ///
    /// fn test(arena: impl Arena) {
    ///     let alloc = arena.store(Some(0)).unwrap().into_mut();
    ///     std::mem::drop(arena);
    ///     let _ = alloc.is_some();
    /// }
    /// ```
    #[allow(dead_code)]
    fn test_ref_borrows_arena() {}
}
