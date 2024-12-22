use std::{
    marker::PhantomData,
    ops::Range,
    sync::{Arc, RwLock},
};

use fxhash::FxHashMap;
use iced_x86::{code_asm::CodeAssembler, DecoderOptions, IcedError, Instruction, OpKind, Register};
use pelite::{
    image::{RUNTIME_FUNCTION, UNWIND_INFO},
    pe::{Pe, PeObject, PeView},
};
use windows::Win32::{
    Foundation::{EXCEPTION_ACCESS_VIOLATION, EXCEPTION_ILLEGAL_INSTRUCTION},
    System::{
        Diagnostics::Debug::{
            AddVectoredExceptionHandler, CONTEXT, EXCEPTION_CONTINUE_EXECUTION,
            EXCEPTION_CONTINUE_SEARCH, EXCEPTION_POINTERS,
        },
        Threading::GetCurrentThreadId,
    },
};

use crate::{
    arena::ArenaAllocAt,
    cfg::ControlFlowGraph,
    iced_ext::Decoder,
    rwe_buffer::{RWEArena, RWEArenaCache},
    thunk::{cconv, StoreThunk},
    trampoline::{Trampoline, TrampolineParams},
    widenable::{Widenable, WidenableMeta, WidenedInstanceLayout, WidenedToAllocator},
    winapi_utils::hmodule_from_ptr,
};

/// Read a general purpose register from a thread context given an [`iced_x86::Register`].
pub fn read_gpr(ctx: &CONTEXT, register: Register) -> Option<u64> {
    let full_reg = match register.full_register() {
        Register::RAX => ctx.Rax,
        Register::RCX => ctx.Rcx,
        Register::RDX => ctx.Rdx,
        Register::RBX => ctx.Rbx,
        Register::RSP => ctx.Rsp,
        Register::RBP => ctx.Rbp,
        Register::RSI => ctx.Rsi,
        Register::RDI => ctx.Rdi,
        Register::R8 => ctx.R8,
        Register::R9 => ctx.R9,
        Register::R10 => ctx.R10,
        Register::R11 => ctx.R11,
        Register::R12 => ctx.R12,
        Register::R13 => ctx.R13,
        Register::R14 => ctx.R14,
        Register::R15 => ctx.R15,
        _ => return None,
    };
    Some(full_reg & (4 << register.size()) - 1)
}

pub struct Context<'a> {
    pub accessed_memory_address: usize,
    pub instruction_bytes: &'a [u8],
    pub original_instruction_address: usize,
    pub instruction: Instruction,
    pub thread_context: &'a CONTEXT,
}

pub struct Builder<Orig: Widenable, Widened: Widenable> {
    phantom: PhantomData<fn() -> (Orig, Widened)>,
    reserved_memory_size: usize,
    alloc_calls: Vec<u64>,
    free_calls: Vec<u64>,
    access_type_heuristic:
        Option<Box<dyn FnMut(&ArrayWidener, &Context) -> WidenedAccessType + Send + Sync>>,
}

impl<O: Widenable, W: Widenable> Default for Builder<O, W> {
    fn default() -> Self {
        const {
            if O::META.widenable_field_layout().layout.size()
                > W::META.widenable_field_layout().layout.size()
            {
                panic!("Original widenable field cannot be larger than widened version");
            }
        };

        Self {
            phantom: PhantomData,
            reserved_memory_size: 1 << 31, // Default 2GiB
            alloc_calls: Default::default(),
            free_calls: Default::default(),
            access_type_heuristic: None,
        }
    }
}

impl<O: Widenable, W: Widenable> Builder<O, W> {
    pub fn reserved_memory_size(self, size: usize) -> Self {
        Self {
            reserved_memory_size: size,
            ..self
        }
    }

    pub fn alloc_calls(mut self, calls: impl IntoIterator<Item = u64>) -> Self {
        self.alloc_calls.extend(calls);
        self
    }

    pub fn free_calls(mut self, calls: impl IntoIterator<Item = u64>) -> Self {
        self.free_calls.extend(calls);
        self
    }

    pub fn access_type_heuristic<F>(self, heuristic: F) -> Self
    where
        F: FnMut(&ArrayWidener, &Context) -> WidenedAccessType + 'static + Send + Sync,
    {
        Self {
            access_type_heuristic: Some(Box::new(heuristic)),
            ..self
        }
    }

    pub fn build(self) -> ArrayWidener {
        let memory_layout = &W::INSTANCE_LAYOUT;
        let field_shift =
            (memory_layout.split_field_shift() + &W::META.split_field_layout().offset) as i64;

        // TODO: Make this work for arbitrary alignment
        let post_field_shift = field_shift
            + (&W::META.widenable_field_layout().end_offset()
                - &O::META.widenable_field_layout().end_offset()) as i64;

        ArrayWidener {
            instance_mem_base: 0,
            instance_mem_size: 0,
            desired_instance_mem_size: self.reserved_memory_size,
            orig_layout: &O::META,
            wide_layout: &W::META,
            alloc_calls: self.alloc_calls,
            free_calls: self.free_calls,
            memory_layout,
            field_shift,
            post_field_shift,
            access_type_heuristic: self.access_type_heuristic,
        }
    }
}

/// Type of field access in a widened type, as determined by an access type heuristic.
pub enum WidenedAccessType {
    /// Access type is unknown.
    Unknown,
    /// Access occurs before the widenable field.
    PreField,
    /// Access occurs within the widenable field.
    InField,
    /// Access occurs after the widenable field.
    PostField,
}

pub struct ArrayWidener {
    pub orig_layout: &'static WidenableMeta,
    pub wide_layout: &'static WidenableMeta,
    pub memory_layout: &'static WidenedInstanceLayout,
    pub instance_mem_base: u64,
    pub instance_mem_size: u64,
    desired_instance_mem_size: usize,
    alloc_calls: Vec<u64>,
    free_calls: Vec<u64>,
    field_shift: i64,
    post_field_shift: i64,
    access_type_heuristic:
        Option<Box<dyn FnMut(&Self, &Context<'_>) -> WidenedAccessType + Send + Sync>>,
}

impl ArrayWidener {
    pub fn new<O: Widenable, W: Widenable>() -> Builder<O, W> {
        Builder::default()
    }

    pub fn handle_access(&mut self, ctx: &Context<'_>, hook_ip: u64) -> Option<Vec<u8>> {
        // Take the heuristic box out of the option so we can pass self to it
        let access_type = match self.access_type_heuristic.take() {
            Some(mut h) => {
                let acces_type = (*h)(self, ctx);
                self.access_type_heuristic = Some(h);
                acces_type
            }
            None => self.default_access_heuristic(ctx),
        };

        let displ_shift = match access_type {
            WidenedAccessType::Unknown => return None,
            WidenedAccessType::PreField | WidenedAccessType::InField => self.field_shift,
            WidenedAccessType::PostField => self.post_field_shift,
        };
        let mut hook_asm = self.conditional_hook(ctx, displ_shift).unwrap();
        Some(hook_asm.assemble(hook_ip).unwrap())
    }

    fn conditional_hook(
        &self,
        ctx: &Context,
        displ_shift: i64,
    ) -> Result<CodeAssembler, IcedError> {
        use iced_x86::code_asm::*;

        // Helper to generate the following code
        // INSTR REG, [RIP+2]
        // JMP 8
        // dq VALUE
        struct InlineDq {
            data_label: CodeLabel,
            post_label: CodeLabel,
        }
        impl InlineDq {
            fn new(asm: &mut CodeAssembler) -> Self {
                Self {
                    data_label: asm.create_label(),
                    post_label: asm.create_label(),
                }
            }

            fn emit(&mut self, asm: &mut CodeAssembler, dq: u64) -> Result<(), IcedError> {
                asm.jmp(self.post_label)?;
                asm.set_label(&mut self.data_label)?;
                asm.dq(&[dq])?;
                asm.set_label(&mut self.post_label)?;
                Ok(())
            }
        }

        let mut asm = CodeAssembler::new(64)?;

        let mut normal_path = asm.create_label();
        let mut end = asm.create_label();

        asm.pushfd()?;
        asm.mov(qword_ptr(rsp - 8), rax)?;

        // Create instruction with same memory operands
        let mut lea = Instruction::with(iced_x86::Code::Lea_r64_m);
        lea.set_op0_register(Register::RAX);
        lea.set_memory_base(ctx.instruction.memory_base());
        lea.set_memory_displ_size(ctx.instruction.memory_displ_size());
        lea.set_memory_displacement64(ctx.instruction.memory_displacement64());
        lea.set_memory_index(ctx.instruction.memory_index());
        lea.set_memory_index_scale(ctx.instruction.memory_index_scale());
        asm.add_instruction(lea)?;

        let mut reserved_mem_start = InlineDq::new(&mut asm);
        asm.add(rax, qword_ptr(reserved_mem_start.data_label))?;
        reserved_mem_start.emit(&mut asm, self.instance_mem_base.wrapping_neg())?;

        if self.instance_mem_size <= u32::MAX as u64 {
            asm.cmp(rax, self.instance_mem_size as i32)?;
            asm.jae(normal_path)?;
        }
        else {
            let mut reserved_mem_size = InlineDq::new(&mut asm);
            asm.cmp(rax, qword_ptr(reserved_mem_size.data_label))?;
            asm.jae(normal_path)?;
            reserved_mem_size.emit(&mut asm, self.instance_mem_size as u64)?;
        }

        asm.and(rax, (self.memory_layout.block_size - 1) as i32)?;
        asm.cmp(rax, (self.memory_layout.commited_bytes_required) as i32)?;
        asm.jb(normal_path)?;

        asm.mov(rax, qword_ptr(rsp - 8))?;
        asm.popfd()?;
        let mut shifted_instr = ctx.instruction;
        shifted_instr.set_memory_displacement64(
            ctx.instruction.memory_displacement64().wrapping_add_signed(displ_shift),
        );
        asm.add_instruction(shifted_instr)?;
        asm.jmp(end)?;

        asm.set_label(&mut normal_path)?;
        asm.mov(rax, qword_ptr(rsp - 8))?;
        asm.popfd()?;
        asm.add_instruction(ctx.instruction)?;

        asm.set_label(&mut end)?;
        Ok(asm)
    }

    /// Default heuristic for determining the memory access type
    pub fn default_access_heuristic(&self, ctx: &Context) -> WidenedAccessType {
        if ctx.instruction.op_kinds().find(|op| op == &OpKind::Memory).is_none() {
            log::error!("Not a memory instruction");
            return WidenedAccessType::Unknown;
        }

        // `WidenedInstanceLayout` layout restriction: size >= align is a power of 2
        let instance_mem_base =
            ctx.accessed_memory_address & !(self.memory_layout.block_size as usize);

        let orig_field_layout = self.orig_layout.widenable_field_layout();
        let wide_field_layout = self.wide_layout.widenable_field_layout();
        let instance_ptr = instance_mem_base + self.memory_layout.struct_ptr_offset;
        let instance_offset = ctx.accessed_memory_address - instance_ptr;

        // Handle the two trivial cases first
        if instance_offset < orig_field_layout.offset {
            return WidenedAccessType::PreField;
        }
        else if instance_offset >= wide_field_layout.end_offset() {
            return WidenedAccessType::PostField;
        }

        let base = ctx.instruction.memory_base();
        let signed_disp = ctx.instruction.memory_displacement64() as i64 as isize;
        let base_addr = read_gpr(&ctx.thread_context, base).unwrap() as usize;
        let base_offset = base_addr - instance_ptr;

        // The memory base is equal to the widenable struct
        // Check within the original bounds
        if base_offset == 0 {
            if signed_disp < orig_field_layout.end_offset() as isize {
                WidenedAccessType::InField
            }
            else {
                WidenedAccessType::PostField
            }
        }
        // The memory base is within the original field
        // This is very likely an access within the field
        else if base_offset >= orig_field_layout.offset
            && base_offset < orig_field_layout.end_offset()
        {
            WidenedAccessType::InField
        }
        else {
            WidenedAccessType::PostField
        }
    }
}

pub struct ArrayWidenerManager {
    array_wideners: Vec<ArrayWidener>,
    codegen_arenas: RWEArenaCache,
    cfg: ControlFlowGraph,
    decoder: Decoder<'static>,
    access_hooks: FxHashMap<u64, u64>,
    original_instruction_addresses: FxHashMap<u64, u64>,
}

impl ArrayWidenerManager {
    pub fn new(codegen_arena_size: usize) -> Self {
        Self {
            array_wideners: Default::default(),
            codegen_arenas: RWEArenaCache::new(codegen_arena_size),
            cfg: ControlFlowGraph::default(),
            // SAFETY: Definitely not safe :)
            decoder: unsafe {
                Decoder::try_with_slice_ptr(
                    64,
                    std::ptr::slice_from_raw_parts(0 as *const _, 1 << 47),
                    0,
                    DecoderOptions::NONE,
                )
                .unwrap()
            },
            access_hooks: Default::default(),
            original_instruction_addresses: Default::default(),
        }
    }

    pub fn register(&mut self, array_widener: ArrayWidener) {
        self.array_wideners.push(array_widener)
    }

    /// Enables the array widener, leaking its memory.
    ///
    /// It is not possible to access or disable the array widener after this has been called.
    pub unsafe fn enable(mut self) {
        // Setup allocator replacements and alloc/free hooks
        for aw in &mut self.array_wideners {
            let alloc = WidenedToAllocator::new(aw.memory_layout, aw.desired_instance_mem_size);
            aw.instance_mem_base = alloc.usable_range().start as u64;
            aw.instance_mem_size = alloc.usable_len() as u64;

            let shared_alloc = Box::leak(Box::new(RwLock::new(alloc)));

            let new_alloc =
                || shared_alloc.write().expect("shared WidenedToAllocator poisoned").alloc();

            let new_free = |ptr| unsafe {
                shared_alloc.write().expect("shared WidenedToAllocator poisoned").free(ptr)
            };

            let mut apply_trampoline = |arena: &mut RWEArena, ip, thunk| {
                let trampoline = Trampoline::new(
                    &mut self.decoder,
                    None,
                    TrampolineParams {
                        hook_ip: thunk,
                        insert_ip: ip,
                        replace_instruction: true,
                        trampoline_memory: arena.avail_buffer(),
                    },
                )
                .unwrap();

                unsafe {
                    trampoline.apply_to_memory();
                }
            };

            for &alloc_call in &aw.alloc_calls {
                let arena = self.codegen_arenas.near_ptr(alloc_call as *const _).unwrap();
                let thunk = arena.store_thunk(cconv::C, new_alloc.clone()).unwrap().leak();
                log::debug!(
                    "hooking alloc call: {:016x} -> {:016x}",
                    alloc_call,
                    thunk as u64
                );
                apply_trampoline(arena, alloc_call, thunk as u64);
            }
            for &alloc_call in &aw.free_calls {
                let arena = self.codegen_arenas.near_ptr(alloc_call as *const _).unwrap();
                let thunk = arena.store_thunk(cconv::C, new_free.clone()).unwrap().leak();
                log::debug!(
                    "hooking free call: {:016x} -> {:016x}",
                    alloc_call,
                    thunk as u64
                );
                apply_trampoline(arena, alloc_call, thunk as u64);
            }
        }

        let arena = Box::leak(Box::new(RWEArena::new(0x1000)));
        let lock = RwLock::new(self);
        let thunk = arena
            .store_thunk(
                cconv::System,
                move |ex_ptrs: *mut EXCEPTION_POINTERS| -> i32 {
                    let mut array_widener_man = lock.write().expect("array widener lock poisoned");
                    unsafe { array_widener_man.handle_exception(ex_ptrs) }
                },
            )
            .unwrap();

        unsafe {
            AddVectoredExceptionHandler(1, Some(thunk.leak()));
        }

        log::info!("ArrayWidenerManager enabled");
    }

    pub unsafe fn handle_exception(&mut self, ex_ptrs: *mut EXCEPTION_POINTERS) -> i32 {
        let thread_context = unsafe { &mut *(*ex_ptrs).ContextRecord };
        let ex_info = unsafe { &*(*ex_ptrs).ExceptionRecord };
        let instruction_address = ex_info.ExceptionAddress as u64;
        let accessed_memory_address = ex_info.ExceptionInformation[1];

        // Ignore nested exceptions
        if !ex_info.ExceptionRecord.is_null() {
            log::error!("nested exception: {:?}", unsafe {
                *ex_info.ExceptionRecord
            });
            return EXCEPTION_CONTINUE_SEARCH;
        }
        else if ex_info.ExceptionCode == EXCEPTION_ILLEGAL_INSTRUCTION {
            log::error!(
                "attempted to execute illegal instruction at {instruction_address:x}, possible array widener bug?"
            );
            return EXCEPTION_CONTINUE_SEARCH;
        }
        else if ex_info.ExceptionCode != EXCEPTION_ACCESS_VIOLATION {
            return EXCEPTION_CONTINUE_SEARCH;
        }

        let array_widener = match self.array_wideners.iter_mut().find(|aw| {
            (aw.instance_mem_base..aw.instance_mem_base + aw.instance_mem_size)
                .contains(&(accessed_memory_address as u64))
        }) {
            None => {
                log::error!(
                    "access violation outside array widener trap memory at {:x} (accessed {:x})",
                    instruction_address,
                    accessed_memory_address
                );
                return EXCEPTION_CONTINUE_SEARCH;
            }
            Some(aw) => aw,
        };

        // In hot multithreaded code, a second thread might hit the instruction before patches are
        // observed. To avoid patching twice, we keep track of existing patches
        if let Some(&new_ip) = self.access_hooks.get(&instruction_address) {
            log::debug!(
                "thread {:x} was waiting at patched location {:x}. Redirecting to {:x}",
                unsafe { GetCurrentThreadId() },
                instruction_address,
                new_ip
            );
            thread_context.Rip = new_ip as u64;
            return EXCEPTION_CONTINUE_EXECUTION;
        }

        let instruction = self.decoder.decode_at(instruction_address).unwrap();
        if instruction.is_invalid() {
            log::error!(
                "iced failed to dissable instruction at {:x}. Error: {:?}",
                instruction_address,
                self.decoder.last_error()
            );
            return EXCEPTION_CONTINUE_SEARCH;
        }

        let arena = match self.codegen_arenas.near_ptr(instruction_address as *const _) {
            Some(a) => a,
            None => {
                log::error!(
                    "failed to find or create a code buffer near {:016x}",
                    instruction_address
                );
                return EXCEPTION_CONTINUE_SEARCH;
            }
        };

        let maybe_cfg = unsafe {
            extend_cfg_if_required(
                &mut self.decoder,
                &mut self.cfg,
                instruction_address,
                thread_context.Rsp,
            )
        }
        .inspect_err(|err| log::warn!("{err}"))
        .ok();

        let instruction_bytes = unsafe {
            std::slice::from_raw_parts(instruction_address as *const _, instruction.len())
        };

        let ctx = Context {
            accessed_memory_address,
            instruction_bytes,
            instruction,
            thread_context,
            original_instruction_address: *self
                .original_instruction_addresses
                .get(&instruction_address)
                .unwrap_or(&instruction_address) as usize,
        };

        let addr_range = arena.avail_address_range();
        let hook_ip = addr_range.start as u64;
        // Let the array widener generate the access hook
        if let Some(hook) = array_widener.handle_access(&ctx, hook_ip) {
            let hook_buf = arena.alloc_at(hook_ip as usize, hook.len()).unwrap();
            unsafe {
                (*hook_buf).copy_from_slice(&hook);
            }

            let trampoline = Trampoline::new(
                &mut self.decoder,
                maybe_cfg.as_ref().map(|x| &**x),
                TrampolineParams {
                    hook_ip,
                    insert_ip: instruction_address,
                    replace_instruction: true,
                    trampoline_memory: arena.avail_buffer(),
                },
            )
            .unwrap();

            unsafe {
                trampoline.apply_to_memory();
            }
            maybe_cfg.map(|cfg| trampoline.fixup_cfg(&mut self.decoder, cfg));

            // Update original instruction addresses map with instruction relocations done by
            // applyting the trampoline
            for (old_ip, new_ip) in &trampoline.relocation_map {
                let original_for_old =
                    *self.original_instruction_addresses.get(old_ip).unwrap_or(old_ip);
                self.original_instruction_addresses.entry(*new_ip).or_insert(original_for_old);
            }

            let new_rip = *trampoline
                .relocation_map
                .get(&trampoline.params.insert_ip)
                .unwrap_or(&trampoline.params.insert_ip);

            self.access_hooks.insert(instruction_address, new_rip);
            thread_context.Rip = new_rip;
        }

        return EXCEPTION_CONTINUE_EXECUTION;
    }
}

/// Tries to extend the control flow graph to cover the given instruction if possible.
///
/// Returns a result representing whether or not the CFG can be used for trampoline generation.
unsafe fn extend_cfg_if_required<'a>(
    decoder: &mut Decoder,
    cfg: &'a mut ControlFlowGraph,
    instr_addr: u64,
    rsp_value: u64,
) -> Result<&'a mut ControlFlowGraph, String> {
    if cfg.is_visited(instr_addr) {
        return Ok(cfg);
    }

    // Try to find the function we're in
    let mod_handle = hmodule_from_ptr(instr_addr as *const _).ok_or_else(|| {
        format!(
            "non-visited instruction outside module at {:016x}, can't compute CFG",
            instr_addr
        )
    })?;
    let mod_addr = mod_handle.0 as u64;

    let pe = unsafe { PeView::module(mod_handle.0 as _) };
    let ex_table = pe.exception().map_err(|err| {
        format!(
            "can't get exception table for module {:016x} ({:?})",
            mod_handle.0 as u64, err
        )
    })?;

    let rva = instr_addr - mod_handle.0 as u64;
    let mod_range = pe.image().as_ptr_range();
    let fn_entry_point = ex_table
        .lookup_function_entry(rva as u32)
        .map(|fun| unsafe {
            // This mess is unsound if the pe file is not valid
            // I also don't care for now
            const UNW_FLAG_CHAININFO: u8 = 0x4;
            let mut fun = fun.image();
            let mut unwind_info = &*((mod_addr + fun.UnwindData as u64) as *const UNWIND_INFO);
            while unwind_info.VersionFlags & UNW_FLAG_CHAININFO != 0 {
                let offset = (unwind_info.CountOfCodes + 1 & !1) as usize;
                fun = &*(unwind_info.UnwindCode.get_unchecked(offset) as *const _
                    as *const RUNTIME_FUNCTION);
                unwind_info = &*((mod_addr + fun.UnwindData as u64) as *const UNWIND_INFO);
            }
            mod_addr + fun.BeginAddress as u64
        })
        .or_else(|| {
            // If instruction is not within the runtime function table, it is part of a leaf
            // function get the return address from rsp and try to resolve
            // function start from a call instruction
            let return_address = rsp_value;
            let call_opcode_addr = (return_address - 5) as *const u8;
            let call_displ_addr = (return_address - 4) as *const u32;

            (mod_range.contains(&((return_address - 1) as *const u8))
                && mod_range.contains(&call_opcode_addr)
                && unsafe { *call_opcode_addr } == 0xE8)
                .then(|| return_address + unsafe { call_displ_addr.read_unaligned() } as u64)
        })
        .ok_or_else(|| {
            format!(
                "cannot find function for instruction at {:016x}",
                instr_addr
            )
        })?;

    cfg.walk(decoder, fn_entry_point);
    Ok(cfg)
}