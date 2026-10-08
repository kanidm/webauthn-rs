use std::path::Path;

use actix_files::NamedFile;
use actix_web::HttpRequest;

pub const ASSETS_DIR: &str = "../axum/assets/js";

pub(crate) async fn serve_assets(req: HttpRequest) -> actix_web::Result<NamedFile> {
    let fp = req.match_info().query("filename");
    let path = Path::new(ASSETS_DIR).join(fp);
    Ok(NamedFile::open(path)?)
}

pub(crate) async fn serve_index(_req: HttpRequest) -> actix_web::Result<NamedFile> {
    let path = Path::new(ASSETS_DIR).join("index.html");
    Ok(NamedFile::open(path)?)
}
