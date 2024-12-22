// |... start fields|invalid for whole object|

use fxhash::{FxHashMap, FxHashSet};
use iced_x86::{BlockEncoder, BlockEncoderOptions, Code, IcedError, Instruction, InstructionBlock};

use crate::{cfg::ControlFlowGraph, iced_ext::Decoder};

#[non_exhaustive]
#[derive(Debug, thiserror::Error)]
pub enum TrampolineGenError {
    #[error("{0}")]
    Iced(#[from] IcedError),
    #[error("emitted code does not fit in trampoline memory")]
    NotEnoughMemory,
    #[error("instruction has no reloc info")]
    NoRelocInfo(u64),
}

pub struct TrampolineParams {
    /// IP of the hook code
    pub hook_ip: u64,
    /// IP at which the jump to the hook should be inserted.
    pub insert_ip: u64,
    /// If true, replaces the existing instruction at `insert_rip` instead of relocating it.
    pub replace_instruction: bool,
    /// Executable memory range where the generated code is to be emitted.
    pub trampoline_memory: *mut [u8],
}

pub struct Trampoline {
    /// Parameters used to generate this trampoline
    pub params: TrampolineParams,
    /// IP at which the hook should jump to return the the original code flow
    pub hook_return_ip: u64,
    /// Pairs of emitted code buffers and addresses at which to write them.
    pub generated_code: Vec<(u64, Vec<u8>)>,
    /// Map of instruction relocations for the purposes of updating a control flow graph.
    pub relocation_map: FxHashMap<u64, u64>,
    /// IP of instructions (or basic blocks) which did not exist in the original code.
    pub new_instructions: Vec<u64>,
}

impl Trampoline {
    pub fn new(
        decoder: &mut Decoder,
        cfg: Option<&ControlFlowGraph>,
        params: TrampolineParams,
    ) -> Result<Self, TrampolineGenError> {
        #[derive(Clone, Copy, Debug)]
        struct MovedInstr {
            instruction: Instruction,
            is_block_start: bool,
        }

        // Instructions that will have to be relocated
        let mut to_move: FxHashMap<u64, MovedInstr> = FxHashMap::default();

        // Do DFS over the reverse CFG (going up xrefs and finding short control flow instructions)
        let mut dfs_queue = vec![params.insert_ip];
        let mut visited = FxHashSet::default();
        let mut instruction = Instruction::default();

        while let Some(rip) = dfs_queue.pop() {
            if !visited.insert(rip) {
                continue;
            }

            decoder.decode_out_at(rip, &mut instruction)?;
            to_move.entry(rip).or_insert(MovedInstr {
                instruction,
                is_block_start: true,
            });

            let mut block_span = instruction.len();
            while block_span < 5 {
                decoder.decode_out(&mut instruction);
                block_span += instruction.len();
                if let Some(cfg) = cfg {
                    dfs_queue.extend_from_slice(cfg.xrefs(instruction.ip()));
                }

                to_move
                    .entry(instruction.ip())
                    .and_modify(|m| m.is_block_start = false)
                    .or_insert(MovedInstr {
                        instruction,
                        is_block_start: false,
                    });
            }
        }

        // Create jmp instruction that goes to the hook
        let jmp = MovedInstr {
            instruction: {
                let mut instr = Instruction::with_branch(Code::Jmp_rel32_64, params.hook_ip)?;
                instr.set_ip(to_move[&params.insert_ip].instruction.ip());
                instr
            },
            ..to_move[&params.insert_ip]
        };

        // Combine hook jmp with instructions to move, while removing IP info from original
        // instruction. This will make the BlockEncoder redirect branches to the jmp hook
        let mut to_move: Vec<_> = std::iter::once(jmp).chain(to_move.into_values()).collect();
        to_move.sort_by_key(|m| m.instruction.ip());

        let pos = to_move.iter().rposition(|m| m.instruction.ip() == params.insert_ip).unwrap();
        if params.replace_instruction {
            to_move.remove(pos);
        }
        else {
            to_move[pos].is_block_start = false;
            to_move[pos].instruction.set_len(0);
            to_move[pos].instruction.set_next_ip(0);
        }

        // if log::STATIC_MAX_LEVEL >= log::Level::Trace {
        //     log::trace!("moving instructions: ");
        //     to_move.iter().for_each(|m| {
        //         log::trace!(
        //             "{:017X} {:?} ({})",
        //             m.instruction.ip(),
        //             m.instruction.code(),
        //             m.is_block_start
        //         )
        //     });
        // }

        // Fixup the relocated instructions block control flow
        let mut in_trampoline = vec![];
        let mut leaf_jmps = vec![];

        // Track where the jmp instruction going to the hook ends up
        let mut hook_ret_offset = 0;
        let mut i_trampoline_block = None;
        let mut i_trampoline_instr = 0;

        for (i, moved) in to_move.iter().enumerate() {
            let instr = &moved.instruction;
            let is_insert_ip = instr.ip() == params.insert_ip;
            let next_is_block_start =
                to_move.get(i + 1).map(|next| next.is_block_start).unwrap_or(true);

            // If instruction is initial jmp into a block
            if moved.is_block_start {
                // If a regular jmp, condition can be inlined
                if instr.is_jmp_short_or_near() {
                    if is_insert_ip && next_is_block_start {
                        i_trampoline_block = Some(leaf_jmps.len());
                        i_trampoline_instr = 0;
                        hook_ret_offset = 5;
                    }
                    else if is_insert_ip {
                        i_trampoline_instr = in_trampoline.len();
                    }
                    leaf_jmps.push((*instr, instr.ip()));
                    continue;
                }
                // Otherwise, we create a jmp to it and insert that one in place
                else {
                    leaf_jmps.push((
                        Instruction::with_branch(Code::Jmp_rel32_64, instr.ip())?,
                        instr.ip(),
                    ));
                }
            }

            if instr.ip() == params.insert_ip {
                i_trampoline_instr = in_trampoline.len();
            }
            in_trampoline.push(*instr);

            // If the next instruction is part of a different block, insert jmp back to original
            // code
            if next_is_block_start {
                in_trampoline.push(Instruction::with_branch(
                    Code::Jmp_rel32_64,
                    instr.next_ip(),
                )?);
            }
        }

        // Collect instruction blocks
        let mut instruction_blocks: Vec<_> = leaf_jmps
            .iter()
            .map(|(instr, ip)| InstructionBlock::new(std::slice::from_ref(instr), *ip))
            .collect();

        instruction_blocks.push(InstructionBlock::new(
            &in_trampoline,
            params.trampoline_memory.addr() as u64,
        ));

        // Use iced-x86's BlockEncoder to re-encode instructions and optimize branches
        let new_blocks = BlockEncoder::encode_slice(
            64,
            &instruction_blocks,
            BlockEncoderOptions::RETURN_ALL_NEW_INSTRUCTION_OFFSETS,
        )?;

        if new_blocks.last().unwrap().code_buffer.len() > params.trampoline_memory.len() {
            return Err(TrampolineGenError::NotEnoughMemory);
        }

        // Create relocation map and new instructions
        let mut new_instructions = vec![];
        let mut relocation_map: FxHashMap<_, _> = leaf_jmps
            .iter()
            .filter_map(|(instr, ip)| {
                if instr.ip() == 0 {
                    new_instructions.push(*ip);
                    None
                }
                else {
                    Some((*ip, *ip))
                }
            })
            .collect();

        let last_block = new_blocks.last().unwrap();
        relocation_map.extend(in_trampoline.iter().enumerate().filter_map(|(i, instr)| {
            let ip = last_block.rip + last_block.new_instruction_offsets[i] as u64;
            if instr.ip() == 0 {
                new_instructions.push(ip);
                None
            }
            else {
                Some((instr.ip(), ip))
            }
        }));

        // Compute return IP
        let hook_return_ip = {
            let block = &new_blocks[i_trampoline_block.unwrap_or(new_blocks.len() - 1)];
            block.rip + block.new_instruction_offsets[i_trampoline_instr] as u64 + hook_ret_offset
        };

        Ok(Self {
            params,
            hook_return_ip,
            generated_code: new_blocks.into_iter().map(|b| (b.rip, b.code_buffer)).collect(),
            relocation_map,
            new_instructions,
        })
    }

    pub unsafe fn apply_to_memory(&self) -> &Self {
        for (ip, block) in self.generated_code.iter().rev() {
            unsafe {
                std::ptr::copy_nonoverlapping(block.as_ptr(), *ip as *mut u8, block.len());
            }
        }
        self
    }

    pub fn fixup_cfg(&self, decoder: &mut Decoder, cfg: &mut ControlFlowGraph) -> &Self {
        cfg.invalidate(self.relocation_map.keys().copied());
        for &new_ip in self.relocation_map.values().chain(self.new_instructions.iter()) {
            cfg.walk(decoder, new_ip);
        }
        self
    }
}
