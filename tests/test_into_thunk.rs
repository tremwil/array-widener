use array_widener::{
    rwe_buffer::RWEArena,
    thunk::{cconv, FnMutThunkable, StoreThunk},
};

#[test]
fn into_thunk_simple() {
    let arena = RWEArena::new(1 << 16);

    let mut data = 420;
    let fetch_add_data = |n: &usize| {
        let old_data = data;
        data += *n;
        old_data
    };

    let thunk = arena.store_mut_thunk(cconv::C(fetch_add_data)).unwrap();
    let bare_fn = thunk.bare_fn();

    assert!(unsafe { bare_fn(&69) } == 420);

    drop(thunk); // Required, as `thunk` mutably borrows `data`!
    assert!(data == 420 + 69);
}
