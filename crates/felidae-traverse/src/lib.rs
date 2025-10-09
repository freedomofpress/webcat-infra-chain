use prost::bytes::Bytes;
use std::any::Any;

pub trait Traverse: Sized + 'static {
    fn traverse(&self, f: &mut impl FnMut(&dyn Any)) {
        f(self as &dyn Any);
    }

    fn traverse_mut(&mut self, f: &mut impl FnMut(&mut dyn Any)) {
        f(self as &mut dyn Any);
    }
}

macro_rules! references {
    // Allow for defining reference types like Box, Arc, etc.
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

macro_rules! primitives {
    ($($t:ty),*) => {
        $(
            impl Traverse for $t {}
        )*
    };
}

references! { Box }
collections! { Option, Vec }
primitives! { String, Bytes, bool, f32, f64, i32, i64, u32, u64 }
