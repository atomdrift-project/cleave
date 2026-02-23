//! Procedural macros for flayer
//!
//! This crate provides derive macros for automatically implementing traits
//! based on struct field definitions.

use proc_macro::TokenStream;
use quote::quote;
use syn::{parse_macro_input, Data, DeriveInput, Fields};

/// Derive macro for ValidFieldPaths trait
///
/// Automatically extracts all public field names from a struct and implements
/// the ValidFieldPaths trait. This ensures field paths stay in sync with
/// struct definitions without manual maintenance.
///
/// # Example
///
/// ```ignore
/// #[derive(ValidFieldPaths)]
/// pub struct BinaryMetrics {
///     pub overall_entropy: f32,
///     pub code_entropy: f32,
/// }
/// ```
///
/// Generates:
///
/// ```ignore
/// impl ValidFieldPaths for BinaryMetrics {
///     fn valid_field_paths() -> Vec<&'static str> {
///         vec!["overall_entropy", "code_entropy"]
///     }
/// }
/// ```
#[proc_macro_derive(ValidFieldPaths)]
pub fn derive_valid_field_paths(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);

    let name = &input.ident;

    // Extract field names from the struct
    let field_names = match &input.data {
        Data::Struct(data_struct) => {
            match &data_struct.fields {
                Fields::Named(fields) => {
                    fields
                        .named
                        .iter()
                        .filter_map(|field| {
                            // Only include public fields
                            if matches!(field.vis, syn::Visibility::Public(_)) {
                                field.ident.as_ref().map(std::string::ToString::to_string)
                            } else {
                                None
                            }
                        })
                        .collect::<Vec<_>>()
                }
                _ => {
                    return syn::Error::new_spanned(
                        name,
                        "ValidFieldPaths can only be derived for structs with named fields",
                    )
                    .to_compile_error()
                    .into();
                }
            }
        }
        _ => {
            return syn::Error::new_spanned(
                name,
                "ValidFieldPaths can only be derived for structs",
            )
            .to_compile_error()
            .into();
        }
    };

    // Generate the implementation
    let expanded = quote! {
        impl crate::types::field_paths::ValidFieldPaths for #name {
            fn valid_field_paths() -> Vec<&'static str> {
                vec![#(#field_names),*]
            }
        }
    };

    TokenStream::from(expanded)
}
