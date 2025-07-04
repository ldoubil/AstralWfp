#[cfg(windows)]
extern crate winres;

#[cfg(windows)]
fn main() {
    let mut res = winres::WindowsResource::new();
    res.set_manifest_file("manifest.xml");
    res.compile().unwrap();
}

#[cfg(not(windows))]
fn main() {} 