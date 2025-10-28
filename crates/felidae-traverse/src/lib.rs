//! A generic traversal trait permitting a type to be visited recursively by reference or by mutable
//! reference.
//!
//! This is used internally in Felidae to permit signatures to bind the entire outer transaction.

use prost::bytes::Bytes;
use std::any::Any;

/// A trait for types that can be visited recursively.
pub trait Traverse: Sized + 'static {
    /// Traverse the type by reference, calling the given function on each visited node.
    fn traverse(&self, f: &mut impl FnMut(&dyn Any)) {
        f(self as &dyn Any);
    }

    /// Traverse the type by mutable reference, calling the given function on each visited node.
    fn traverse_mut(&mut self, f: &mut impl FnMut(&mut dyn Any)) {
        f(self as &mut dyn Any);
    }
}

/// Implement Traverse for a reference type.
macro_rules! references {
    ($($t:tt),*) => {
        $(
            impl<T: Traverse> Traverse for $t<T> {
                fn traverse(&self, f: &mut impl FnMut(&dyn Any)) {
                    (**self).traverse(f);
                    f(self as &dyn Any);
                }

                fn traverse_mut(&mut self, f: &mut impl FnMut(&mut dyn Any)) {
                    (**self).traverse_mut(f);
                    f(self as &mut dyn Any);
                }
            }
        )*
    };
}

/// Implement Traverse for a type that can be iterated over.
macro_rules! collections {
    ($($t:tt),*) => {
        $(
            impl<T: Traverse> Traverse for $t<T> {
                fn traverse(&self, f: &mut impl FnMut(&dyn Any)) {
                    for v in self.iter() {
                        v.traverse(f);
                    }
                    f(self as &dyn Any);
                }

                fn traverse_mut(&mut self, f: &mut impl FnMut(&mut dyn Any)) {
                    for v in self.iter_mut() {
                        v.traverse_mut(f);
                    }
                    f(self as &mut dyn Any);
                }
            }
        )*
    };
}

/// Implement Traverse for a type that contains nothing traversable within.
macro_rules! primitives {
    ($($t:ty),*) => {
        $(
            impl Traverse for $t {}
        )*
    };
}

// Implement Traverse for reference types, collections, and primitive types of relevance to
// generated protobuf code. Add more `std` types here as needed:

references! { Box }
collections! { Option, Vec }
primitives! { String, Bytes, bool, f32, f64, i32, i64, u32, u64 }
