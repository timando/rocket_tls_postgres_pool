use rocket::serde::Deserialize;

#[derive(Deserialize, Copy, Clone)]
#[serde(crate = "rocket::serde")]
#[serde(rename_all="kebab-case")]
enum VerifyMode{
    NoVerify,
    VerifyCa,
    VerifyFull,
}

#[cfg(feature="rustls")]
mod rustls;

#[cfg(feature="rustls")]
pub use rustls::TlsPool as RustlsPool;

#[cfg(feature="native-tls")]
mod native_tls;

#[cfg(feature="native-tls")]
pub use native_tls::TlsPool as NativeTlsPool;

