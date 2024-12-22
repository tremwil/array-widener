use case::CaseExt;
use proc_macro::TokenStream;
use proc_macro2 as pm2;
use proc_macro_error::{abort, abort_call_site, emit_error, proc_macro_error};
use quote::quote;
use syn::{parse_macro_input, visit_mut::VisitMut};

/// Implements [`array_widener::widenable::Widenable`] for a type.
///
/// The field that supports widening must be marked with the `#[widenable]` attribute. Only
/// one field can be widenable.
/// 
/// When a struct is widened, a new type with memory layout matching the widened type will be generated.
/// This type can be obtained via the [`array_widener::widenable::WidenedTo<T>`] type alias. The actual 
/// layout of this type splits the fields in two to create the following:
/// ```txt
/// | (padding) | split field and up | (padding) | pre-split fields | no-access memory |
/// ```
/// This layout is what allows the array widener to detect memory access to the widenable field. By default,
/// the split occurs at the `#[widenable]` field. However, depending on the alignment of previous fields, it
/// may be impossible to get this layout to work. In such cases, your code will fail to compile and you will
/// have to manually define the split point using the `#[split_here]` attribute.
/// 
/// Example:
///
/// ```
/// #[derive(Widenable)]
/// struct PartyMemberInfo<const N: usize> {
///     vftable: usize,
///     pub white_ghosts: u64,
///     pub black_ghosts: u64,
///     pub detective_ghosts: u64,
///
///     #[split_here]
///     #[widenable]
///     pub party_members: [PartyMember; N],
///
///     unk0: u64,
///     unk1: u64,
///     // and more
/// }
/// ```
#[proc_macro_error]
#[proc_macro_derive(Widenable, attributes(widenable, split_here))]
pub fn derive_widenable(items: TokenStream) -> TokenStream {
    let input = parse_macro_input!(items as syn::DeriveInput);

    let struct_data = match &input.data {
        syn::Data::Enum(enum_data) => {
            abort!(enum_data.enum_token, "Enums cannot be Widenable")
        }
        syn::Data::Union(union_data) => {
            abort!(union_data.union_token, "Unions cannot be Widenable")
        }
        syn::Data::Struct(struct_data) => struct_data,
    };

    let vis = &input.vis;
    let ident = &input.ident;
    let (impl_generics, ty_generics, where_clause) = &input.generics.split_for_impl();

    let mut fields: Vec<_> = match &struct_data.fields {
        syn::Fields::Unit => abort_call_site!("Unit structs cannot be Widenable"),
        syn::Fields::Unnamed(fields) => abort!(fields, "Widenable type must have named fields"),
        syn::Fields::Named(fields) => &fields.named,
    }
    .iter()
    .map(|f| f.clone())
    .collect();

    let (w_field_index, _, _) = get_opt_attr_target(fields.iter_mut(), "widenable")
        .unwrap_or_else(|| {
            abort_call_site!("Widenable type must have exactly one #[widenable] field")
        });

    let split_index = get_opt_attr_target(fields.iter_mut(), "split_here")
        .inspect(|(i, _, attr)| {
            if *i > w_field_index {
                abort!(attr, "#[split_here] cannot be inserted after #[widenable]");
            }
        })
        .map(|(i, _, _)| i)
        .unwrap_or(w_field_index);

    struct SuperPathAdapter<'a> {
        self_ident: &'a syn::Ident,
        self_generics: &'a syn::TypeGenerics<'a>,
    }
    impl<'a> VisitMut for SuperPathAdapter<'a> {
        fn visit_path_mut(&mut self, path: &mut syn::Path) {
            if path.leading_colon.is_some() {
                return;
            }

            let num_segments = path.segments.len();
            if let Some(seg) = path.segments.first_mut() {
                let ident = seg.ident.to_string();
                if ident == "crate" || ident == "std" {
                    return;
                }
                else if ident == "Self" {
                    let ident = self.self_ident;
                    let generics = self.self_generics;
                    *seg = syn::parse2(quote! { #ident #generics }).unwrap();
                }
                else if num_segments == 1 {
                    return;
                }
            }

            let tail = path.segments.clone();
            path.segments.clear();
            path.segments.push(syn::Token![super](pm2::Span::call_site()).into());
            path.segments.extend(tail);
        }

        fn visit_vis_restricted_mut(&mut self, vis: &mut syn::VisRestricted) {
            if vis.path.is_ident("self") {
                *vis.path = syn::Token![super](pm2::Span::call_site()).into();
            }
            else {
                self.visit_path_mut(&mut vis.path);
            }
        }

        fn visit_visibility_mut(&mut self, vis: &mut syn::Visibility) {
            match vis {
                // Full public visibility, no changes
                syn::Visibility::Public(_) => (),
                // Inherited visibility needs to be promoted to pub(super)
                syn::Visibility::Inherited => {
                    *vis = syn::Visibility::Restricted(syn::VisRestricted {
                        pub_token: syn::Token![pub](pm2::Span::call_site()),
                        paren_token: syn::token::Paren::default(),
                        in_token: None,
                        path: Box::new(syn::Token![super](pm2::Span::call_site()).into()),
                    })
                }
                syn::Visibility::Restricted(r) => self.visit_vis_restricted_mut(r),
            };
        }
    }

    let mut super_adapter = SuperPathAdapter {
        self_ident: ident,
        self_generics: ty_generics,
    };

    let mut make_struct_fields = |fields: &[syn::Field]| {
        fields
            .iter()
            .map(|f| {
                let mut f = (*f).clone();
                super_adapter.visit_field_mut(&mut f);
                f
            })
            .collect::<syn::punctuated::Punctuated<_, syn::Token![,]>>()
    };

    let pre_split_fields = make_struct_fields(&fields[..split_index]);
    let post_split_fields = make_struct_fields(&fields[split_index..]);

    let mut adapted_vis = input.vis.clone();
    super_adapter.visit_visibility_mut(&mut adapted_vis);

    let mut adapted_generics = input.generics.clone();
    super_adapter.visit_generics_mut(&mut adapted_generics);
    let (adapted_impl_generics, adapted_ty_generics, adapted_where_clause) =
        adapted_generics.split_for_impl();

    let mod_ident = syn::Ident::new(
        &format!("_widenable_detail_{}", ident.to_string().to_snake()),
        pm2::Span::call_site(),
    );

    fn make_field_layout(field: &syn::Field) -> proc_macro2::TokenStream {
        let field_ident = &field.ident;
        let field_ty = &field.ty;
        quote! {
            ::array_widener::widenable::FieldLayout {
                offset: ::std::mem::offset_of!(Self, #field_ident),
                layout: ::std::alloc::Layout::new::<#field_ty>()
            }
        }
    }

    let field_layouts = fields.iter().map(make_field_layout);
    let all_field_idents: Vec<_> = fields.iter().map(|f| &f.ident).collect();
    let pre_split_field_itents: Vec<_> = fields[..split_index].iter().map(|f| &f.ident).collect();
    let post_split_field_itents: Vec<_> = fields[split_index..].iter().map(|f| &f.ident).collect();

    quote! {
        impl #impl_generics ::array_widener::widenable::Widenable for #ident #ty_generics  where #where_clause {
            const META: ::array_widener::widenable::WidenableMeta = ::array_widener::widenable::WidenableMeta {
                self_layout: ::std::alloc::Layout::new::<Self>(),
                fields: &[#(#field_layouts),*],
                widenable_index: #w_field_index,
                split_index: #split_index,
            };

            const INSTANCE_LAYOUT: ::array_widener::widenable::WidenedInstanceLayout = 
                ::array_widener::widenable::WidenedInstanceLayout::new(&Self::META);

            type WidenedTo = #mod_ident::_Widened_PreSplit #ty_generics;

            unsafe fn write_to_widened(self, widened: *mut Self::WidenedTo) {
                #((&raw mut (*widened).#all_field_idents).write(self.#all_field_idents);)*
            }

            unsafe fn read_to_widened(widened: *const Self::WidenedTo) -> Self {
                let mut instance = ::std::mem::MaybeUninit::<Self>::uninit();
                let as_ptr = instance.as_mut_ptr();

                let offset = Self::INSTANCE_LAYOUT.split_field_shift();
                let post_split = (widened as usize - offset) as *const #mod_ident::_Widened_PostSplit #ty_generics;

                #((&raw mut(*as_ptr).#pre_split_field_itents)
                    .write((&raw const (*widened).#pre_split_field_itents).read());)*
                #((&raw mut (*as_ptr).#post_split_field_itents)
                    .write((&raw const (*post_split).#post_split_field_itents).read());)*
                
                instance.assume_init()
            }
        }

        #vis mod #mod_ident {
            use super::*;

            #[allow(non_camel_case_types)]
            #[repr(C)]
            #adapted_vis struct _Widened_PreSplit #adapted_generics {
                _widenable_force_self_align: [super::#ident #adapted_ty_generics; 0],
                _widenable_noconstruct: (),
                #pre_split_fields,
            }

            #[allow(non_camel_case_types)]
            #[repr(C)]
            #adapted_vis struct _Widened_PostSplit #adapted_generics {
                _widenable_use_generics: ::std::marker::PhantomData<super::#ident #adapted_ty_generics>,
                _widenable_noconstruct: (),
                #post_split_fields,
            }

            impl #adapted_impl_generics ::std::ops::Deref for _Widened_PreSplit #adapted_ty_generics
                #adapted_where_clause
            {
                type Target = _Widened_PostSplit #adapted_ty_generics;

                fn deref(&self) -> &Self::Target {
                    let offset = const {
                        <super::#ident #adapted_ty_generics as ::array_widener::widenable::Widenable>
                        ::INSTANCE_LAYOUT.split_field_shift()
                    };
                    unsafe {
                        let ptr = self as *const _ as usize;
                        &*((ptr - offset) as *const _)
                    }
                }
            }

            impl #adapted_impl_generics ::std::ops::DerefMut for _Widened_PreSplit #adapted_ty_generics
                #adapted_where_clause
            {
                fn deref_mut(&mut self) -> &mut Self::Target {
                    let offset = const {
                        <super::#ident #adapted_ty_generics as ::array_widener::widenable::Widenable>
                        ::INSTANCE_LAYOUT.split_field_shift()
                    };
                    unsafe {
                        let ptr = self as *mut _ as usize;
                        &mut *((ptr - offset) as *mut _)
                    }
                }
            }
        }
    }
    .into()
}

fn get_opt_attr_target<'a>(
    fields: impl IntoIterator<Item = &'a mut syn::Field>,
    ident: &str,
) -> Option<(usize, syn::Field, syn::Attribute)> {
    let with_attr: Vec<_> = fields
        .into_iter()
        .enumerate()
        .filter_map(|(i, field)| {
            let mut target_attr = None;
            field.attrs.retain(|attr| {
                if attr.meta.path().is_ident(ident) {
                    target_attr = Some(attr.clone());
                    false
                }
                else {
                    true
                }
            });
            target_attr.map(|attr| (i, field, attr))
        })
        .collect();

    match with_attr.len() {
        0 | 1 => with_attr.into_iter().next().map(|(i, f, a)| (i, f.clone(), a)),
        _ => {
            for (_, _, attr) in with_attr {
                emit_error!(attr, format!("Only one #[{ident}] attribute is allowed"));
            }
            abort_call_site!(format!("Only one #[{ident}] attribute is allowed"));
        }
    }
}