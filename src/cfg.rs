use fxhash::{FxHashMap, FxHashSet};
use iced_x86::{FlowControl, Instruction};

use crate::iced_ext::Decoder;

/// Types of flow control branching, ignoring call semantics.
#[derive(Debug, Default, Clone)]
pub enum NonCallBranch {
    /// RET instruction
    #[default]
    Return,
    /// Indirect jump, e.g. JMP [RAX]
    IndirectJump,
    /// Interrupt (e.g. INT3) or exception (e.g. invalid opcode, UDn)
    Interrupt,
    /// JMP instruction
    UncondJump { target: u64 },
    /// JCC instruction
    CondJump { target: u64 },
    /// Switch statement, i.e. indirect jump based on static table lookup
    Switch { targets: Box<[u64]> },
}

impl NonCallBranch {
    pub fn has_fallthrough(&self) -> bool {
        match self {
            Self::CondJump { target: _ } => true,
            _ => false,
        }
    }

    pub fn targets(&self) -> &[u64] {
        match self {
            Self::Return | Self::IndirectJump | Self::Interrupt => &[],
            Self::UncondJump { target } | Self::CondJump { target } => std::slice::from_ref(target),
            Self::Switch { targets } => targets,
        }
    }

    pub fn targets_mut(&mut self) -> &mut [u64] {
        match self {
            Self::IndirectJump | Self::Interrupt | Self::Return => &mut [],
            Self::UncondJump { target } | Self::CondJump { target } => std::slice::from_mut(target),
            Self::Switch { targets } => targets,
        }
    }
}

/// Control flow graph describing all non-implicit branches inside a single function, excluding
/// calls.
///
/// Essentially, it contains the minimal information required to detect if an instruction is a
/// branch target, and how to locate the branches that point to it.
#[derive(Debug, Default, Clone)]
pub struct ControlFlowGraph {
    branches: FxHashMap<u64, NonCallBranch>,
    xrefs: FxHashMap<u64, Vec<u64>>,
    instructions: FxHashSet<u64>,
}

impl ControlFlowGraph {
    pub fn branch(&self, addr: u64) -> Option<&NonCallBranch> {
        self.branches.get(&addr)
    }

    pub fn xrefs(&self, addr: u64) -> &[u64] {
        self.xrefs.get(&addr).map(|refs| refs.as_slice()).unwrap_or(&[])
    }

    pub fn is_branch(&self, addr: u64) -> bool {
        self.branches.contains_key(&addr)
    }

    pub fn is_target(&self, addr: u64) -> bool {
        self.xrefs.contains_key(&addr)
    }

    pub fn is_visited(&self, addr: u64) -> bool {
        self.instructions.contains(&addr)
    }

    pub fn update_addresses(&mut self, relocations: &FxHashMap<u64, u64>) {
        let replace_addrs = |addrs: &mut [u64]| {
            addrs.iter_mut().for_each(|addr| *addr = *relocations.get(addr).unwrap_or(addr));
        };

        for (&old, &new) in relocations {
            if !self.instructions.remove(&old) {
                continue;
            }
            self.instructions.insert(new);

            if let Some(mut branch) = self.branches.remove(&old) {
                replace_addrs(branch.targets_mut()); // Handle self-referring branches
                for xrefs_addr in branch.targets() {
                    self.xrefs.get_mut(xrefs_addr).map(|x| replace_addrs(x));
                }
                self.branches.insert(new, branch);
            }

            if let Some(mut xrefs) = self.xrefs.remove(&old) {
                replace_addrs(&mut xrefs); // Handle self-referring branches
                for branch_addr in xrefs.iter() {
                    self.branches.get_mut(branch_addr).map(|b| replace_addrs(b.targets_mut()));
                }
                self.xrefs.insert(new, xrefs);
            }
        }
    }

    pub fn invalidate(&mut self, addresses: impl IntoIterator<Item = u64>) {
        let addresses: FxHashSet<u64> = addresses.into_iter().collect();
        let mut xrefs_done: FxHashSet<u64> = FxHashSet::default();
        for addr in &addresses {
            self.instructions.remove(&addr);
            self.xrefs.remove(&addr);
            if let Some(branch) = self.branches.remove(&addr) {
                for target in branch.targets().iter().filter(|t| xrefs_done.insert(**t)) {
                    self.xrefs
                        .get_mut(target)
                        .map(|xrefs| xrefs.retain(|x| !addresses.contains(x)));
                }
            }
        }
    }

    pub fn walk(&mut self, decoder: &mut Decoder, ip: u64) {
        let mut instruction = Instruction::default();

        let mut target_stack = vec![ip];
        while let Some(ip) = target_stack.pop() {
            if !self.instructions.insert(ip) {
                continue;
            }

            if decoder.set_pos_from_ip(ip).is_err() || !decoder.can_decode() {
                log::warn!(
                    "Exited decoder region during control flow analysis at {:016x}",
                    ip
                );
                continue;
            }
            decoder.decode_out(&mut instruction);
            let next_ip = instruction.next_ip();

            let branch = match instruction.flow_control() {
                FlowControl::Return => NonCallBranch::Return,
                FlowControl::IndirectBranch => NonCallBranch::IndirectJump,
                FlowControl::Exception | FlowControl::Interrupt => {
                    if instruction.is_invalid() {
                        log::warn!("Invalid opcode hit during control flow analysis at {ip:016x}");
                    }
                    NonCallBranch::Interrupt
                }
                FlowControl::UnconditionalBranch => {
                    let target = instruction.near_branch_target();
                    target_stack.push(target);

                    NonCallBranch::UncondJump { target }
                }
                FlowControl::ConditionalBranch => {
                    let target = instruction.near_branch_target();
                    target_stack.push(target);
                    target_stack.push(next_ip);

                    NonCallBranch::CondJump { target }
                }
                _ => {
                    target_stack.push(next_ip);
                    continue;
                }
            };

            for &target in branch.targets() {
                self.xrefs.entry(target).or_default().push(ip);
            }
            self.branches.insert(ip, branch);
        }
    }
}
