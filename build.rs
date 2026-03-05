use std::env;
use std::error::Error;
use std::fs::File;
use std::path::PathBuf;

fn main() {
    println!("cargo:rerun-if-changed=assets/icon_16.png");
    println!("cargo:rerun-if-changed=assets/icon_32.png");
    println!("cargo:rerun-if-changed=assets/icon_64.png");

    let target_os = env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    if target_os != "windows" {
        return;
    }

    if let Err(error) = embed_windows_icon() {
        panic!("Failed to embed Windows icon: {error}");
    }
}

fn embed_windows_icon() -> Result<(), Box<dyn Error>> {
    let out_dir = PathBuf::from(env::var("OUT_DIR")?);
    let icon_path = out_dir.join("eternalrust_app.ico");

    let mut icon_dir = ico::IconDir::new(ico::ResourceType::Icon);

    for source in [
        "assets/icon_16.png",
        "assets/icon_32.png",
        "assets/icon_64.png",
    ] {
        let image = image::open(source)?.into_rgba8();
        let (width, height) = image.dimensions();
        let icon_image = ico::IconImage::from_rgba_data(width, height, image.into_raw());
        let icon_entry = ico::IconDirEntry::encode(&icon_image)?;
        icon_dir.add_entry(icon_entry);
    }

    let mut icon_file = File::create(&icon_path)?;
    icon_dir.write(&mut icon_file)?;

    let mut res = winres::WindowsResource::new();
    res.set_icon(icon_path.to_str().ok_or("Invalid icon path")?);
    res.compile()?;

    Ok(())
}
