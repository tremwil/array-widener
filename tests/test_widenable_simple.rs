use std::alloc::Layout;

use array_widener::widenable::{Widenable, PAGE_SIZE};

#[repr(C)]
struct PartyMember {
    party_member_handle: u64,
    unk_08: u64,
    unk_10: u64,
    unk_18: u32,
    unk_1c: u8,
    unk_20: u32,
    unk_24: u8,
    unk_28: u32,
}

#[repr(C)]
#[derive(Widenable)]
struct PartyMemberInfo<const N: usize> {
    vftable: usize,
    white_ghosts: u64,
    black_ghosts: u64,
    detective_ghosts: u64,
    #[widenable]
    party_members: [PartyMember; N],
    unk_148: u64,
    unk_150: u64,
    unk_158: u64,
    unk_160: u64,
    unk_168: u64,
    unk_170: u64,
    unk_178: u32,
    unk_17c: u32,
    unk_180: u64,
    unk_188: u32,
    unk_18c: u8,
    unk_190: u32,
}

// extern "C" {
//     fn original_pmi_ctor(this: *mut PartyMemberInfo<6>) -> *mut PartyMemberInfo<6>;
//     fn original_pmi_dtor(this: *mut PartyMemberInfo<6>);
// }

// unsafe extern "C" fn ctor_hook(
//     this: *mut WidenedTo<PartyMemberInfo<127>>,
// ) -> *mut WidenedTo<PartyMemberInfo<127>> {
//     let original_pmi = MaybeUninit::<PartyMemberInfo<6>>::uninit();
//     original_pmi_ctor(original_pmi.as_mut_ptr());
//     let original_pmi = original_pmi.assume_init();

//     let extra_array_elements = make_extra_elements(&mut original_pmi);
//     let expanded_pmi = PartyMemberInfo::<127> { /* Build from orig_pmi and extra_array_elements
// */};

//     expanded_pmi.write_to_widened(this);
//     this
// }

#[test]
fn test_instance_layout() {
    type PMI = PartyMemberInfo<127>;

    let meta = PMI::META;
    let instance = PMI::INSTANCE_LAYOUT;
    println!("{:#?}", &meta);
    println!("{:#?}", &instance);

    assert_eq!(meta.self_layout, Layout::new::<PMI>());
    assert_eq!(meta.split_index, 4);
    assert_eq!(meta.widenable_index, 4);

    assert_eq!(instance.block_size, 4 * PAGE_SIZE as u32);
    assert_eq!(instance.commited_bytes_required, 2 * PAGE_SIZE);
    assert_eq!(instance.split_field_offset, 0);
    assert_eq!(instance.struct_ptr_offset, 8160);
    assert_eq!(instance.split_field_shift(), 8160);
}
