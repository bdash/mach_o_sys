use std::{
    collections::{HashMap, HashSet},
    error::Error,
    ffi::OsStr,
    io::Write,
    path::PathBuf,
    process::Command,
};

use itertools::Itertools;
use regex::Regex;

struct Header {
    absolute: String,
    relative: String,
}

fn find_mach_o_header_directory() -> Result<PathBuf, Box<dyn Error>> {
    let sdk_path = Command::new("xcrun")
        .arg("--show-sdk-path")
        .output()?
        .stdout;
    let sdk_path = String::from_utf8(sdk_path)?;
    let sdk_path = sdk_path.trim_end();
    Ok(PathBuf::from(sdk_path).join("usr/include/mach-o"))
}

fn find_mach_o_headers() -> Result<Vec<Header>, Box<dyn Error>> {
    let mach_o_header_directory = find_mach_o_header_directory()?;

    let mut headers = Vec::new();
    for entry in walkdir::WalkDir::new(&mach_o_header_directory)
        .min_depth(1)
        .sort_by_file_name()
    {
        if let Ok(entry) = entry {
            if entry.file_type().is_dir() || entry.path().extension() != Some(OsStr::new("h")) {
                continue;
            }

            let relative = entry
                .path()
                .strip_prefix(&mach_o_header_directory)?
                .to_str()
                .unwrap()
                .to_string();

            // Skip i386/swap.h. The functions it provides are rarely used
            // and depend on a large number of complex struct definitions
            // from outside of the mach-o headers.
            if relative == "i386/swap.h" {
                continue;
            }

            headers.push(Header {
                absolute: entry.path().to_str().unwrap().to_string(),
                relative,
            });
        }
    }

    Ok(headers)
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum ItemHandling {
    Allow(String),
    Block(String),
}

fn header_specific_additions(
    header: &Header,
) -> Result<(HashSet<String>, HashSet<ItemHandling>), Box<dyn Error>> {
    let mut imports = HashSet::new();
    let mut items = HashSet::new();

    let header_contents = std::fs::read_to_string(&header.absolute)?;

    if header.relative != "loader.h" && header.relative != "fat.h" {
        let libc_types = Regex::new(r"(uuid_t|mach_port_t|cpu_subtype_t|cpu_type_t)").unwrap();
        for capture in libc_types.captures_iter(&header_contents) {
            let libc_type = capture.get(1).unwrap().as_str();
            imports.insert("extern crate libc;".to_string());
            imports.insert(format!("use self::libc::{libc_type};"));
        }
    };

    let mach_o_includes = Regex::new(r"#include <mach-o/(.*?)\.h>").unwrap();
    for include in mach_o_includes.captures_iter(&header_contents) {
        imports.insert(format!(
            "use crate::{}::*;",
            include.get(1).unwrap().as_str()
        ));
    }

    if header_contents.contains("NXByteOrder") {
        // A few headers reference NXByteOrder from <architecture/byte_order.h>, but
        // that isn't exposed anywhere. Let arch.h define it, and have other modules
        // reference it there.
        if header.relative == "arch.h" {
            items.insert(ItemHandling::Allow("NXByteOrder".to_string()));
        } else {
            imports.insert("use crate::arch::NXByteOrder;".to_string());
        }
    }

    if header.relative == "dyld_images.h" {
        // dyld_images.h contains forward declarations of struct mach_header.
        // Have it reference the definition in loader rather than defining
        // an incompatible placeholder to represent the forward declaration.
        imports.insert("use crate::loader::mach_header;".to_string());
        items.insert(ItemHandling::Block("mach_header".to_string()));
    }

    Ok((imports, items))
}

fn main() -> Result<(), Box<dyn Error>> {
    let args: Vec<String> = std::env::args().collect();
    let out_path = &args[1];
    let out_path = PathBuf::from(out_path);

    let headers = find_mach_o_headers()?;

    let mut modules: HashMap<PathBuf, Vec<String>> = HashMap::new();

    for header in headers {
        eprint!("Processing {}...", header.relative);

        let (imports, items) = header_specific_additions(&header)?;

        let mut module_attributes = HashSet::new();
        module_attributes.insert(
            "#![allow(dead_code,
         non_camel_case_types,
         non_upper_case_globals,
         non_snake_case)]"
                .to_string(),
        );

        let mut builder = bindgen::Builder::default()
            .header(&header.absolute)
            .allowlist_file(&header.absolute)
            .allowlist_recursively(false)
            .merge_extern_blocks(true)
            .default_enum_style(bindgen::EnumVariation::Rust {
                non_exhaustive: false,
            })
            .formatter(bindgen::Formatter::None)
            .derive_default(true)
            .layout_tests(false);

        for item in items {
            builder = match item {
                ItemHandling::Allow(name) => builder.allowlist_item(name),
                ItemHandling::Block(name) => builder.blocklist_item(name),
            };
        }

        let builder = module_attributes
            .iter()
            .sorted()
            .chain(imports.iter().sorted())
            .fold(builder, |builder, line| builder.raw_line(line));

        let bindings = builder.generate().expect("Unable to generate bindings");

        let rust_src_path = PathBuf::from(&header.relative.replace(".h", ".rs").replace("-", "_"));

        // Make sure the module ends up in mod.rs / lib.rs
        let parent_module = rust_src_path.parent().unwrap().to_path_buf();
        let rust_module = rust_src_path
            .file_stem()
            .unwrap()
            .to_str()
            .unwrap()
            .to_string();
        let entry = modules.entry(parent_module.clone()).or_default();
        entry.push(rust_module);

        // Ensure nested modules end up in lib.rs
        if parent_module.as_os_str() != "" {
            let entry = modules.entry("".into()).or_default();
            entry.push(parent_module.to_str().unwrap().to_string());
        }

        let out_file = out_path.join(&rust_src_path);
        std::fs::create_dir_all(out_file.parent().unwrap())?;
        bindings
            .write_to_file(&out_file)
            .expect("Couldn't write bindings!");
        Command::new("rustfmt")
            .args(&[
                "--config",
                "group_imports=StdExternalCrate,imports_granularity=Crate",
            ])
            .arg(out_file.to_str().unwrap())
            .status()?;

        eprintln!("  done!");
    }

    for (base_path, mut modules) in modules {
        modules.sort();
        let mut module_file = std::fs::File::create(out_path.join(base_path.join(
            if base_path.as_os_str() == "" {
                "lib.rs"
            } else {
                "mod.rs"
            },
        )))?;
        for module in modules {
            writeln!(module_file, "pub mod {module};")?;
        }
    }

    Ok(())
}
