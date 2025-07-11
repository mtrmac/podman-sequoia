extern crate cbindgen;

use std::env;
use std::path::PathBuf;

use anyhow::Result;
use regex::Regex;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Generate
    // ${CARGO_TARGET_DIR}/${PROFILE}/podman-sequoia{-uninstalled}.pc
    // from ${SRC}/podman-sequoia.pc.in.

    let src = env::current_dir()?;

    // Location of the build directory (e.g.,
    // `/tmp/podman-sequoia/debug`).
    let mut build_dir = PathBuf::from(&src);
    if let Some(target_dir) = env::var_os("CARGO_TARGET_DIR") {
        // Note: if CARGO_TARGET_DIR is absolute, this will first
        // clear build_dir, which is what we want.
        build_dir.push(target_dir);
    } else {
        build_dir.push("target");
    }
    let profile = env::var_os("PROFILE").expect("PROFILE not set");
    build_dir.push(&profile);

    let bindings_dir = build_dir.join("bindings");
    let include = bindings_dir.join("sequoia.h");

    // Generate ${CARGO_TARGET_DIR}/${PROFILE}/bindings/sequoia.h
    cbindgen::Builder::new()
        .with_crate(&src)
        .with_language(cbindgen::Language::C)
        .with_header("// SPDX-License-Identifier: LGPL-2.0-or-later")
        .with_pragma_once(true)
        .generate()
        .expect("Unable to generate bindings")
        .write_to_file(&include);

    // Generate dlwrap files
    dlwrap::Builder::new(&include)
        .output_dir(&bindings_dir)
        .symbol_regex(&Regex::new("^sequoia_")?)
	.license("SPDX-License-Identifier: LGPL-2.0-or-later")
	.loader_basename("gosequoia")
	.soname("SEQUOIA_SONAME")
	.prefix("go_sequoia")
	.function_prefix("go")
	.header_guard("GO_SEQUOIA_H_")
	.include("<sequoia.h>")
        .generate()?;

    let prefix = env::var_os("PREFIX");
    let prefix: &str = match prefix.as_ref().map(|s| s.to_str()) {
        Some(Some(s)) => s,
        Some(None) => Err(anyhow::anyhow!("PREFIX contains invalid UTF-8"))?,
        None => "/usr/local",
    };
    let libdir = env::var_os("LIBDIR");
    let libdir: &str = match libdir.as_ref().map(|s| s.to_str()) {
        Some(Some(s)) => s,
        Some(None) => Err(anyhow::anyhow!("LIBDIR contains invalid UTF-8"))?,
        None => "${prefix}/lib",
    };

    // Rerun if...
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=Cargo.toml");
    println!("cargo:rerun-if-env-changed=PREFIX");
    println!("cargo:rerun-if-env-changed=LIBDIR");
    println!("cargo:rerun-if-env-changed=PROFILE");
    println!("cargo:rerun-if-env-changed=CARGO_TARGET_DIR");

    // Set the soname.
    let arch = env::var("CARGO_CFG_TARGET_ARCH").unwrap();
    let os = env::var("CARGO_CFG_TARGET_OS").unwrap();
    let env = env::var("CARGO_CFG_TARGET_ENV").unwrap();

    // We do not care about `_pre` and such.
    let major = env::var("CARGO_PKG_VERSION_MAJOR").unwrap();
    let minor = env::var("CARGO_PKG_VERSION_MINOR").unwrap();
    let patch = env::var("CARGO_PKG_VERSION_PATCH").unwrap();

    // libdir might contain "${prefix}". Replace it with
    // the actual prefix value if found.
    let libdir_resolved = libdir.replace("${prefix}", prefix);

    let linker_lines = cdylib_link_lines::shared_object_link_args(
        "podman_sequoia",
        &major,
        &minor,
        &patch,
        &arch,
        &os,
        &env,
        PathBuf::from(libdir_resolved),
        build_dir.clone(),
    );

    for line in linker_lines {
        println!("cargo:rustc-cdylib-link-arg={}", line);
    }

    #[cfg(unix)]
    {
        // Create a symlink.
        let mut create = true;

        let mut link = build_dir.clone();
        link.push(format!("libpodman_sequoia.so.{}", major));

        if let Ok(current) = std::fs::read_link(&link) {
            if current.to_str() == Some("libpodman_openpgp_sequoia.so") {
                // Do nothing.
                create = false;
            } else {
                // Invalid.
                std::fs::remove_file(&link)?;
            }
        }

        if create {
            std::os::unix::fs::symlink("libpodman_sequoia.so", link)?;
        }
    }
    Ok(())
}
