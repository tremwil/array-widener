use std::{arch::asm, ops::Deref};

use seq_macro::seq;

use crate::arena::{ArenaExt, ArenaRef, ExecArena};

const CLOSURE_ADDR_MAGIC: usize = 0xf6f6531b15b0e802;

/// Trait implemented by a thunkable [`FnMut`] implementor.
///
/// Due to the limitations of the Rust typesystem, it is only implemented for functions of up to 11
/// arguments.
///
/// # Safety
/// The contract that must be held by implementors is not public. Do *not* implement this trait.
pub unsafe trait FnMutThunkable<BareFn: Copy> {
    /// Thunk which calls an (invalid) instance of the `Self`. Used as a template for generating a
    /// more specific code by copying a portion of the instructions and replacing the instance
    /// pointer.
    ///
    /// # Safety
    /// Do not call this directly. **It will always crash!** Use the function provided by
    /// [`IntoMutThunk::into_mut_thunk`] instead.
    const MUT_THUNK: BareFn;
}

/// Trait implemented by a thunkable [`Fn`] implementor
///
/// Due to the limitations of the Rust typesystem, it is only implemented for functions of up to 11
/// arguments.
///
/// # Safety
/// The contract that must be held by implementors is not public. Do *not* implement this trait.
pub unsafe trait FnThunkable<BareFn: Copy>: FnMutThunkable<BareFn> {
    /// Thunk which calls an (invalid) instance of the `Self`. Used as a template for generating a
    /// more specific code by copying a portion of the instructions and replacing the instance
    /// pointer.
    ///
    /// # Safety
    /// Do not call this directly. **It will always crash!** Use the function provided by
    /// [`IntoThunk::into_thunk`] instead.
    const THUNK: BareFn;
}

/// Calling conventions wrappers that can wrap a closure before passing it
/// [`StoreThunk::store_mut_thunk`] and [`StoreThunk::store_thunk`] to help with type inference.
pub mod cconv {
    #[allow(unused_imports)]
    use super::StoreThunk;

    /// The `"C"` calling convention.
    #[repr(transparent)]
    pub struct C<F>(pub F);

    /// The `"system"` calling convention.
    #[repr(transparent)]
    pub struct System<F>(pub F);

    /// The `"sysv64"` calling convention.
    #[cfg(all(not(windows), target_pointer_width = "64", target_arch = "x86_64"))]
    #[repr(transparent)]
    pub struct Sysv64<F>(pub F);

    /// The `"fastcall"` calling convention.
    #[cfg(windows)]
    #[repr(transparent)]
    pub struct Fastcall<F>(pub F);

    /// The `"stdcall"` calling convention.
    #[cfg(windows)]
    #[repr(transparent)]
    pub struct Stdcall<F>(pub F);

    /// The `"cdecl"` calling convention.
    #[cfg(windows)]
    #[repr(transparent)]
    pub struct Cdecl<F>(pub F);

    /// The `"thiscall"` calling convention.
    #[cfg(all(windows, target_pointer_width = "32"))]
    #[repr(transparent)]
    pub struct Thiscall<F>(pub F);

    /// The `"win64"` calling convention.
    #[cfg(all(windows, target_pointer_width = "64"))]
    #[repr(transparent)]
    pub struct Win64<F>(pub F);
}

macro_rules! fn_thunkable_impl {
    ($cconv:path[$cconv_lit:literal] ($($id_tys: ident,)*) ($($args:ident: $tys:ty,)*)) => {
        unsafe impl<F: FnMut($($tys),*) -> R, R, $($id_tys),*> FnMutThunkable<unsafe extern $cconv_lit fn($($tys,)*) -> R> for F {
            const MUT_THUNK: unsafe extern $cconv_lit fn($($tys,)*) -> R = {
                unsafe extern $cconv_lit fn thunk<F: FnMut($($tys),*) -> R, R, $($id_tys),*>($($args: $tys),*) -> R {
                    unsafe {
                        let mut closure_ptr: *mut F;
                        asm!(
                            "movabsq ${cl_magic}, {cl_addr}",
                            "movabsq $2f, {jmp_addr}",
                            "jmp *{jmp_addr}",
                            "2:",
                            cl_addr = out(reg) closure_ptr,
                            cl_magic = const CLOSURE_ADDR_MAGIC,
                            jmp_addr = out(reg) _,
                            options(nostack, att_syntax)
                        );
                        (*closure_ptr)($($args),*)
                    }
                }
                thunk::<F, R, $($tys),*>
            };
        }

        unsafe impl<F: FnMutThunkable<unsafe extern $cconv_lit fn($($tys,)*) -> R>, R, $($id_tys),*> FnMutThunkable<unsafe extern $cconv_lit fn($($tys,)*) -> R> for $cconv {
            const MUT_THUNK: unsafe extern $cconv_lit fn($($tys,)*) -> R = F::MUT_THUNK;
        }

        unsafe impl<F: Fn($($tys),*) -> R, R, $($id_tys),*> FnThunkable<unsafe extern $cconv_lit fn($($tys,)*) -> R> for F {
            const THUNK: unsafe extern $cconv_lit fn($($tys,)*) -> R  = {
                unsafe extern $cconv_lit fn thunk<F: Fn($($tys),*) -> R, R, $($id_tys),*>($($args: $tys),*) -> R {
                    unsafe {
                        let closure_ptr: *const F;
                        asm!(
                            "movabsq ${cl_magic}, {cl_addr}",
                            "movabsq $2f, {jmp_addr}",
                            "jmp *{jmp_addr}",
                            "2:",
                            cl_addr = out(reg) closure_ptr,
                            cl_magic = const CLOSURE_ADDR_MAGIC,
                            jmp_addr = out(reg) _,
                            options(nostack, att_syntax)
                        );
                        (*closure_ptr)($($args),*)
                    }
                }
                thunk::<F, R, $($tys),*>
            };
        }

        unsafe impl<F: FnThunkable<unsafe extern $cconv_lit fn($($tys,)*) -> R>, R, $($id_tys),*> FnThunkable<unsafe extern $cconv_lit fn($($tys,)*) -> R> for $cconv {
            const THUNK: unsafe extern $cconv_lit fn($($tys,)*) -> R = F::THUNK;
        }
    };
}

seq!(M in 0..12 {
    #(
        seq!(N in 0..M {
            #[cfg(target_arch = "x86_64")] // For now
            fn_thunkable_impl! { cconv::C<F>["C"] (#(T~N,)*) (#(a~N: T~N,)*) }

            #[cfg(target_arch = "x86_64")] // For now
            fn_thunkable_impl! { cconv::System<F>["system"] (#(T~N,)*) (#(a~N: T~N,)*) }

            #[cfg(all(not(windows), target_pointer_width = "64", target_arch = "x86_64"))]
            fn_thunkable_impl! { cconv::Sysv64<F>["sysv64"] (#(T~N,)*) (#(a~N: T~N,)*) }

            #[cfg(windows)]
            fn_thunkable_impl! { cconv::Fastcall<F>["fastcall"] (#(T~N,)*) (#(a~N: T~N,)*) }

            #[cfg(windows)]
            fn_thunkable_impl! { cconv::Stdcall<F>["stdcall"] (#(T~N,)*) (#(a~N: T~N,)*) }

            #[cfg(windows)]
            fn_thunkable_impl! { cconv::Cdecl<F>["cdecl"] (#(T~N,)*) (#(a~N: T~N,)*) }

            #[cfg(all(windows, target_pointer_width = "32"))]
            fn_thunkable_impl! { cconv::Thiscall<F>["thiscall"] (#(T~N,)*) (#(a~N: T~N,)*) }

            #[cfg(all(windows, target_pointer_width = "64"))]
            fn_thunkable_impl! { cconv::Win64<F>["win64"] (#(T~N,)*) (#(a~N: T~N,)*) }
        });
    )*
});

unsafe fn store_thunk_common<'a, Arena, F, BareFn: Copy>(
    rwe_buf: &'a Arena,
    closure: F,
    thunk_template: BareFn,
) -> Result<ThunkRef<'a, F, BareFn>, Arena::Error>
where
    Arena: ExecArena + ?Sized,
    F: FnMutThunkable<BareFn> + 'a,
{
    let closure_ref = rwe_buf.store(closure)?;
    let thunk_start: *const u8 = unsafe { std::mem::transmute_copy(&thunk_template) };

    let mut cl_addr_index = 0;
    while unsafe {
        thunk_start.add(cl_addr_index).cast::<usize>().read_unaligned() != CLOSURE_ADDR_MAGIC
    } {
        cl_addr_index += 1;
    }

    // 8 bytes of imm64 + 10 bytes for the next movabs + 2 bytes for the jump = 20 bytes
    let compiled_thunk = unsafe { std::slice::from_raw_parts(thunk_start, cl_addr_index + 20) };
    let copied_thunk = rwe_buf.copy_slice(compiled_thunk)?;

    // write closure ptr to closure address
    (&mut copied_thunk[cl_addr_index..cl_addr_index + 8])
        .copy_from_slice(&(closure_ref.as_const_ptr() as usize).to_le_bytes());

    Ok(ThunkRef {
        bare_fn: unsafe { std::mem::transmute_copy(&copied_thunk.as_ptr()) },
        closure_ref,
    })
}

/// Wrapper binding a closure's bare function thunk to itself for safety purposes.
///
/// A [`Deref`] implementation is provided for convenience, but it is clearer to use
/// [`ThunkRef::bare_fn`] explicitly.
pub struct ThunkRef<'a, F: FnMutThunkable<BareFn> + 'a, BareFn: Copy> {
    closure_ref: ArenaRef<'a, F>,
    bare_fn: BareFn,
}

impl<'a, F: FnMutThunkable<BareFn> + 'a, BareFn: Copy> ThunkRef<'a, F, BareFn> {
    /// Return the bare function stored in this [`ThunkRef`].
    ///
    /// # Safety
    /// When calling the resulting unsafe bare function pointer, you assert that:
    /// - The bare function is never used past the lifetime of `self`;
    /// - When capturing by reference, rust aliasing rules are respected;
    /// - In the case of an [`FnMut`], no concurrent executions are performed.
    #[inline(always)]
    pub fn bare_fn(&self) -> BareFn {
        self.bare_fn
    }

    /// Return the bare function stored in this [`ThunkRef`], consuming self. Any memory allocated
    /// by the closure will be leaked as its destructor will not run.
    ///
    /// # Safety
    /// When calling the resulting unsafe bare function pointer, you assert that:
    /// - The bare function is never used past the lifetime of `self`;
    /// - When capturing by reference, rust aliasing rules are respected;
    /// - In the case of an [`FnMut`], no concurrent executions are performed.
    pub fn leak(self) -> BareFn {
        self.closure_ref.leak();
        self.bare_fn
    }
}

impl<'a, F: FnMutThunkable<BareFn> + 'a, BareFn: Copy> Deref for ThunkRef<'a, F, BareFn> {
    type Target = BareFn;

    #[inline(always)]
    fn deref(&self) -> &Self::Target {
        &self.bare_fn
    }
}

/// Extension trait for [`Arena`] allocators that provides methods for creating bare function thunks
/// for arbitrary closures.
pub trait StoreThunk: ExecArena {
    /// Generate a unsafe bare function thunk which invokes an [`FnMut`] closure.
    ///
    /// The resulting bare function is wrapped in a lifetime-bound [`ThunkRef`] to preven potential
    /// use-after free bugs.
    ///
    /// # Safety
    /// When calling the resulting unsafe bare function pointer, you assert that:
    /// - The bare function is never used past the lifetime of `self`;
    /// - When capturing by reference, rust aliasing rules are respected;
    /// - The bare function is never invoked concurrently.
    #[inline(always)]
    #[allow(unused_variables)]
    fn store_mut_thunk<'a, F: FnMutThunkable<BareFn> + 'a, BareFn: Copy>(
        &'a self,
        fun: F,
    ) -> Result<ThunkRef<'a, F, BareFn>, Self::Error> {
        unsafe { store_thunk_common(self, fun, F::MUT_THUNK) }
    }

    /// Generate a unsafe bare function thunk which invokes an [`Fn`] closure.
    ///
    /// The resulting bare function is wrapped in a lifetime-bound [`ThunkRef`] to preven potential
    /// use-after free bugs.
    ///
    /// # Safety
    /// When calling the resulting unsafe bare function, you assert that:
    /// - The bare function is never used past the lifetime of `self`;
    /// - When capturing by reference, rust aliasing rules are respected.
    #[inline(always)]
    #[allow(unused_variables)]
    fn store_thunk<'a, F: FnThunkable<BareFn> + 'a, BareFn: Copy>(
        &'a self,
        fun: F,
    ) -> Result<ThunkRef<'a, F, BareFn>, Self::Error> {
        unsafe { store_thunk_common(self, fun, F::THUNK) }
    }
}

impl<A: ExecArena + ?Sized> StoreThunk for A {}

mod tests {
    /// Make sure that creating a thunk for a closure mutably capturing a variable can't alias the
    /// variable when dropped.
    ///
    /// ```compile_fail
    /// use array_widener::thunk::StoreThunk;
    /// use array_widener::arena::ExecArena;
    ///
    /// fn test(arena: &impl ExecArena) {
    ///     let mut data = 420;
    ///     let fetch_add_data = |n: &usize| {
    ///         let old_data = data;
    ///         data += *n;
    ///         old_data
    ///     };
    ///     let thunk = arena.store_mut_thunk(fetch_add_data).unwrap();
    ///     data += 69;
    /// }
    /// ```
    #[allow(dead_code)]
    fn closure_drop_check_borrows() {}
}
