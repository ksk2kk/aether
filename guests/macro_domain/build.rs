fn main() {
    println!("cargo:rustc-link-arg=-Tguests/macro_domain/link.x");
    println!("cargo:rerun-if-changed=guests/macro_domain/link.x");
}