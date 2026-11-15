//! What is done ahead of the crate: with feature `notify-templates`, the messengers' templates
//! are read from a TOML file and written out as Rust (build/notify_templates.rs); and in every
//! build, a change of the messages (locales/) is made a reason to compile again.

#[cfg(feature = "notify-templates")]
#[path = "build/notify_templates.rs"]
mod notify_templates;

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    // The messages (locales/*.yml) are read by a macro when the crate is compiled, and cargo does
    // not see that: a build with other features kept the texts it was first compiled with. A
    // change there now runs this script again, and the crate is compiled anew.
    println!("cargo:rerun-if-changed=locales");
    println!("cargo:rerun-if-env-changed=SIGNON_NOTIFY_TEMPLATES");
    #[cfg(feature = "notify-templates")]
    notify_templates::run();
}
