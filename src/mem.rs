//! glibc keeps freed memory in per-thread arenas; after a scan that churned through filters on
//! several threads the daemon would sit at a gigabyte of RSS it no longer uses. Few arenas, and a
//! trim when a scan ends, keep it near what is live. No-ops off glibc.

#[cfg(all(target_os = "linux", target_env = "gnu"))]
pub fn setup() {
    // SAFETY: mallopt is thread-safe and only sets an allocator tunable; arenas created before
    // this call keep existing, which is fine (the cap applies to the ones created afterwards).
    unsafe {
        libc::mallopt(libc::M_ARENA_MAX, 4);
    }
}

#[cfg(all(target_os = "linux", target_env = "gnu"))]
pub fn trim() {
    // SAFETY: malloc_trim(0) releases free heap pages back to the OS; it has no preconditions.
    unsafe {
        libc::malloc_trim(0);
    }
}

#[cfg(not(all(target_os = "linux", target_env = "gnu")))]
pub fn setup() {}

#[cfg(not(all(target_os = "linux", target_env = "gnu")))]
pub fn trim() {}
