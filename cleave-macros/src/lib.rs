//! Procedural macros for cleave
//!
//! This crate provides derive macros for automatically implementing traits
//! based on struct field definitions.

use proc_macro::TokenStream;
use proc_macro_crate::{crate_name, FoundCrate};
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
    let crate_path = match crate_name("cleave") {
        Ok(FoundCrate::Itself) => quote!(crate),
        Ok(FoundCrate::Name(name)) => {
            let ident = syn::Ident::new(&name, proc_macro2::Span::call_site());
            quote!(::#ident)
        }
        Err(_) => quote!(::cleave),
    };

    // Extract field names and doc comments from the struct
    let fields_data: Vec<(String, String)> = match &input.data {
        Data::Struct(data_struct) => {
            match &data_struct.fields {
                Fields::Named(fields) => {
                    fields
                        .named
                        .iter()
                        .filter_map(|field| {
                            if !matches!(field.vis, syn::Visibility::Public(_)) {
                                return None;
                            }
                            let name = field.ident.as_ref()?.to_string();
                            // Collect the first paragraph of /// doc lines (stop at
                            // the first blank `///` line, like rustdoc does).
                            let doc: String = {
                                let lines: Vec<String> = field
                                    .attrs
                                    .iter()
                                    .filter(|a| a.path().is_ident("doc"))
                                    .filter_map(|a| {
                                        if let syn::Meta::NameValue(nv) = &a.meta {
                                            if let syn::Expr::Lit(lit) = &nv.value {
                                                if let syn::Lit::Str(s) = &lit.lit {
                                                    return Some(s.value());
                                                }
                                            }
                                        }
                                        None
                                    })
                                    .map(|s| s.trim().to_string())
                                    .collect();
                                lines
                                    .into_iter()
                                    .take_while(|s| !s.is_empty())
                                    .collect::<Vec<_>>()
                                    .join(" ")
                            };
                            Some((name, doc))
                        })
                        .collect()
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

    let field_names: Vec<&str> = fields_data.iter().map(|(n, _)| n.as_str()).collect();
    let field_docs: Vec<&str> = fields_data.iter().map(|(_, d)| d.as_str()).collect();

    let expanded = quote! {
        impl #crate_path::types::field_paths::ValidFieldPaths for #name {
            fn valid_field_paths() -> Vec<&'static str> {
                vec![#(#field_names),*]
            }

            fn field_descriptions() -> Vec<(&'static str, &'static str)> {
                vec![#((#field_names, #field_docs)),*]
            }
        }
    };

    TokenStream::from(expanded)
}
