use std::fs;
use std::io::Result;

fn main() -> Result<()> {
    let mut proto_files = Vec::new();

    for entry in fs::read_dir("src/")? {
        let entry = entry?;
        let path = entry.path();
        if path.extension().and_then(|s| s.to_str()) == Some("proto")
            && let Some(path_str) = path.to_str()
        {
            proto_files.push(path_str.to_string());
        }
    }

    if !proto_files.is_empty() {
        let proto_refs: Vec<&str> = proto_files.iter().map(|s| s.as_str()).collect();
        prost_build::Config::new()
            .bytes(["."])
            .type_attribute(".", "#[derive(::felidae_traverse_derive::Traverse, ::serde::Serialize, ::serde::Deserialize)]")
            .compile_protos(&proto_refs, &["src/"])?;
    }

    Ok(())
}
