//! rageterm's global allocator wipes every heap block before handing it back.
//!
//! Plaintext reaches buffers rageterm does not own: arboard keeps the
//! clipboard value in its X11/Wayland server state, serde and the standard
//! library copy strings as they grow. None of those zeroize on drop, and
//! rageterm cannot reach them to do it. Wiping on free covers them all: the
//! moment a library releases its copy, the bytes are gone. A block that moves
//! on `realloc` goes through `dealloc` too (the default `realloc` allocates,
//! copies and frees), so growing a buffer does not strand the old one.

use std::alloc::{GlobalAlloc, Layout};

use zeroize::Zeroize;

pub struct WipeOnFree<A>(pub A);

// SAFETY: every call forwards to the inner allocator with the same arguments;
// `dealloc` only writes zeros into the `layout.size()` bytes the caller still
// owns before forwarding.
unsafe impl<A: GlobalAlloc> GlobalAlloc for WipeOnFree<A> {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // SAFETY: the caller's contract for `alloc`, passed on unchanged.
        unsafe { self.0.alloc(layout) }
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        // SAFETY: the caller's contract for `alloc_zeroed`, passed on unchanged.
        unsafe { self.0.alloc_zeroed(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        // SAFETY: `ptr` is a live block of `layout` from this allocator (the
        // `dealloc` contract), so its `layout.size()` bytes are writable until
        // it is handed back on the next line.
        unsafe {
            std::slice::from_raw_parts_mut(ptr, layout.size()).zeroize();
            self.0.dealloc(ptr, layout);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::alloc::System;
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// Counts blocks that reach the system allocator still holding data.
    struct Inspecting;

    static DIRTY_FREES: AtomicUsize = AtomicUsize::new(0);

    // SAFETY: forwards to `System`, reading a block before freeing it.
    unsafe impl GlobalAlloc for Inspecting {
        unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
            // SAFETY: the caller's contract, passed on to `System`.
            unsafe { System.alloc(layout) }
        }

        unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
            // SAFETY: `ptr` is a live block of `layout` until freed below.
            unsafe {
                if std::slice::from_raw_parts(ptr, layout.size())
                    .iter()
                    .any(|b| *b != 0)
                {
                    DIRTY_FREES.fetch_add(1, Ordering::SeqCst);
                }
                System.dealloc(ptr, layout);
            }
        }
    }

    unsafe fn filled(a: &impl GlobalAlloc, layout: Layout) -> *mut u8 {
        // SAFETY: `layout` is non-zero-sized; the new block is ours to fill.
        unsafe {
            let p = a.alloc(layout);
            assert!(!p.is_null());
            std::ptr::write_bytes(p, 0xA5, layout.size());
            p
        }
    }

    #[test]
    fn freed_and_moved_blocks_reach_the_system_allocator_wiped() {
        let small = Layout::from_size_align(64, 8).unwrap();
        let large = Layout::from_size_align(1 << 16, 8).unwrap();
        // SAFETY: each block is freed once, with the layout it was made with.
        unsafe {
            let p = filled(&Inspecting, small);
            Inspecting.dealloc(p, small);
        }
        assert_eq!(
            DIRTY_FREES.swap(0, Ordering::SeqCst),
            1,
            "the inspector must see an unwiped block"
        );

        let a = WipeOnFree(Inspecting);
        // SAFETY: as above; each `realloc` is given the block's current layout.
        unsafe {
            let p = filled(&a, small);
            a.dealloc(p, small);

            let p = filled(&a, small);
            let grown = a.realloc(p, small, large.size());
            std::ptr::write_bytes(grown, 0x5A, large.size());
            let shrunk = a.realloc(grown, large, small.size());
            a.dealloc(shrunk, small);
        }
        assert_eq!(DIRTY_FREES.load(Ordering::SeqCst), 0);
    }
}
