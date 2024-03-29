use std::path::PathBuf;

use actix_files::NamedFile;
use actix_web::HttpRequest;

pub const WASM_DIR: &str = "../../wasm/pkg";

pub(crate) async fn serve_wasm(req: HttpRequest) -> actix_web::Result<NamedFile> {
    let fp: PathBuf = req.match_info().query("filename").parse().unwrap();
    let path = PathBuf::new().join(WASM_DIR).join(fp);
    Ok(NamedFile::open(path)?)
}
