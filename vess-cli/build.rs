#[cfg(windows)]
fn main() {
    println!("cargo:rerun-if-changed=vessicon.ico");

    let mut resource = winresource::WindowsResource::new();
    resource.set_icon("vessicon.ico");
    resource.set("FileDescription", "Vess");
    resource.set("ProductName", "Vess");

    if let Err(error) = resource.compile() {
        panic!("failed to embed Windows executable icon: {error}");
    }
}

#[cfg(not(windows))]
fn main() {}
