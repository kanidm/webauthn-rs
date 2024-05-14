use std::path::Path;

use actix_files::NamedFile;
use actix_web::HttpRequest;

pub const WASM_DIR: &str = "../../wasm/pkg";

pub(crate) async fn serve_wasm(req: HttpRequest) -> actix_web::Result<NamedFile> {
    let fp = req.match_info().query("filename");
    let path = Path::new(WASM_DIR).join(fp);
    Ok(NamedFile::open(path)?)
}
