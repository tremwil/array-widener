use array_widener::Widenable;

#[repr(C)]
pub struct PartyMember {
    field_ins_handle: u64,
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
pub struct PartyMemberInfo<const N: usize> {
    vftable: usize,
    white_phantom_count: u32,
    red_phantom_count: u32,
    loaded_players_count: u32,
    phantom_count: u32,
    player_count: u32,
    all_player_count: u32,
    session_player_count: u32,
    unk_024: u32,
    #[widenable]
    party_members: [PartyMember; N],
    field_ins_handle: [u64; 5],
    ceremony_host_entities_count: u32,
    ceremony_state: u32,
    ceremony_host_id: u32,
    ceremony_event_flag: u32,
    ceremony_host_plus_10k: u32,
    fmg_entry_id: u32,
    unk_188: u64,
    unk_190: u64,
    unk_198: u64,
    unk_1a0: u64,
}

const _ASSERT_PMI_SIZE: () = {
    if std::mem::size_of::<PartyMemberInfo<6>>() != 0x1a8 {
        panic!("Incorrect PartyMemberInfo size");
    }
};
