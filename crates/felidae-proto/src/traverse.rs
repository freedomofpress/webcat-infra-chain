use prost::bytes::Bytes;
use std::any::Any;

pub trait TraverseMut: Sized + 'static {
    fn traverse_mut(&mut self, f: &mut impl FnMut(&mut dyn Any)) {
        f(self as &mut dyn Any);
    }
}

macro_rules! references {
    // Allow for defining reference types like Box, Arc, etc.
    ($($t:tt),*) => {
        $(
            impl<T: TraverseMut> TraverseMut for $t<T> {
                fn traverse_mut(&mut self, f: &mut impl FnMut(&mut dyn Any)) {
                    (**self).traverse_mut(f);
                    f(self as &mut dyn Any);
                }
            }
        )*
    };
}

macro_rules! collections {
    ($($t:tt),*) => {
        $(
            impl<T: TraverseMut> TraverseMut for $t<T> {
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

macro_rules! primitives {
    ($($t:ty),*) => {
        $(
            impl TraverseMut for $t {}
        )*
    };
}

references! { Box }
collections! { Option, Vec }
primitives! { String, Bytes, bool, f32, f64, i32, i64, u32, u64 }
