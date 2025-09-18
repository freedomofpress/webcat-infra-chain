use proc_macro::TokenStream;
use quote::quote;
use syn::{parse_macro_input, Data, DeriveInput, Fields, Index};

#[proc_macro_derive(Traverse)]
pub fn derive_traverse(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    let name = &input.ident;
    let generics = &input.generics;
    let (impl_generics, ty_generics, where_clause) = generics.split_for_impl();

    let (traverse_impl, traverse_mut_impl) = match &input.data {
        Data::Struct(data_struct) => match &data_struct.fields {
            Fields::Named(fields) => {
                let field_names: Vec<_> = fields.named.iter().map(|f| &f.ident).collect();
                let traverse_impl = quote! {
                    let Self { #(#field_names),* } = self;
                    #(#field_names.traverse(f);)*
                    f(self as &dyn ::std::any::Any);
                };
                let traverse_mut_impl = quote! {
                    let Self { #(#field_names),* } = self;
                    #(#field_names.traverse_mut(f);)*
                    f(self as &mut dyn ::std::any::Any);
                };
                (traverse_impl, traverse_mut_impl)
            }
            Fields::Unnamed(fields) => {
                let field_indices: Vec<_> = (0..fields.unnamed.len()).map(Index::from).collect();
                let traverse_impl = quote! {
                    #(self.#field_indices.traverse(f);)*
                    f(self as &dyn ::std::any::Any);
                };
                let traverse_mut_impl = quote! {
                    #(self.#field_indices.traverse_mut(f);)*
                    f(self as &mut dyn ::std::any::Any);
                };
                (traverse_impl, traverse_mut_impl)
            }
            Fields::Unit => {
                let traverse_impl = quote! {
                    f(self as &dyn ::std::any::Any);
                };
                let traverse_mut_impl = quote! {
                    f(self as &mut dyn ::std::any::Any);
                };
                (traverse_impl, traverse_mut_impl)
            }
        },
        Data::Enum(data_enum) => {
            let traverse_variants: Vec<_> = data_enum
                .variants
                .iter()
                .map(|variant| {
                    let variant_name = &variant.ident;
                    match &variant.fields {
                        Fields::Named(fields) => {
                            let field_names: Vec<_> =
                                fields.named.iter().map(|f| &f.ident).collect();
                            quote! {
                                Self::#variant_name { #(#field_names),* } => {
                                    #(#field_names.traverse(f);)*
                                }
                            }
                        }
                        Fields::Unnamed(fields) => {
                            let field_vars: Vec<_> = (0..fields.unnamed.len())
                                .map(|i| {
                                    syn::Ident::new(
                                        &format!("v{i}"),
                                        proc_macro2::Span::call_site(),
                                    )
                                })
                                .collect();
                            quote! {
                                Self::#variant_name(#(#field_vars),*) => {
                                    #(#field_vars.traverse(f);)*
                                }
                            }
                        }
                        Fields::Unit => {
                            quote! {
                                Self::#variant_name => {}
                            }
                        }
                    }
                })
                .collect();

            let traverse_mut_variants: Vec<_> = data_enum
                .variants
                .iter()
                .map(|variant| {
                    let variant_name = &variant.ident;
                    match &variant.fields {
                        Fields::Named(fields) => {
                            let field_names: Vec<_> =
                                fields.named.iter().map(|f| &f.ident).collect();
                            quote! {
                                Self::#variant_name { #(#field_names),* } => {
                                    #(#field_names.traverse_mut(f);)*
                                }
                            }
                        }
                        Fields::Unnamed(fields) => {
                            let field_vars: Vec<_> = (0..fields.unnamed.len())
                                .map(|i| {
                                    syn::Ident::new(
                                        &format!("v{i}"),
                                        proc_macro2::Span::call_site(),
                                    )
                                })
                                .collect();
                            quote! {
                                Self::#variant_name(#(#field_vars),*) => {
                                    #(#field_vars.traverse_mut(f);)*
                                }
                            }
                        }
                        Fields::Unit => {
                            quote! {
                                Self::#variant_name => {}
                            }
                        }
                    }
                })
                .collect();

            let traverse_impl = quote! {
                match self {
                    #(#traverse_variants)*
                }
                f(self as &dyn ::std::any::Any);
            };

            let traverse_mut_impl = quote! {
                match self {
                    #(#traverse_mut_variants)*
                }
                f(self as &mut dyn ::std::any::Any);
            };

            (traverse_impl, traverse_mut_impl)
        }
        Data::Union(_) => {
            return syn::Error::new_spanned(&input, "Traverse cannot be derived for unions")
                .to_compile_error()
                .into();
        }
    };

    let expanded = quote! {
        impl #impl_generics felidae_traverse::Traverse for #name #ty_generics #where_clause {
            fn traverse(&self, f: &mut impl FnMut(&dyn ::std::any::Any)) {
                #traverse_impl
            }

            fn traverse_mut(&mut self, f: &mut impl FnMut(&mut dyn ::std::any::Any)) {
                #traverse_mut_impl
            }
        }
    };

    TokenStream::from(expanded)
}
