// `sqlx::migrate!` embeds `migrations/` when the crate compiles, but cargo
// doesn't know it reads that directory: without this, a new migration
// alone doesn't rebuild the server, and an incremental build (a cached
// Docker target, a developer's) ships a binary without it.
fn main() {
    println!("cargo:rerun-if-changed=migrations");
}
