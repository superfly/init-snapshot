/// Helper to combine multiple filters together with Filter::or, possibly boxing the types in
/// the process. This greatly helps the build times for `ipfs-http`.
/// Source: https://github.com/seanmonstar/warp/issues/619#issuecomment-662716377
#[macro_export]
macro_rules! combine {
    ($x:expr $(,)?) => { boxed_on_debug!($x) };
    ($($x:expr),+ $(,)?) => {
        combine!(@internal ; $($x),+; $($x),+)
    };
    (@internal $($left:expr),*; $head:expr, $($tail:expr),+; $a:expr $(,$b:expr)?) => {
        (combine!($($left,)* $head)).or(combine!($($tail),+))
    };
    (@internal $($left:expr),*; $head:expr, $($tail:expr),+; $a:expr, $b:expr, $($more:expr),+) => {
        combine!(@internal $($left,)* $head; $($tail),+; $($more),+)
    };
}

#[macro_export]
#[cfg(debug_assertions)]
macro_rules! boxed_on_debug {
    ($x:expr) => {
        $x.boxed()
    };
}
