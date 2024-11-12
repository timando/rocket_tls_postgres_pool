use rocket::figment::Figment;
use rocket::tokio;
use rocket_db_pools::{deadpool_postgres, Error, Config};
use deadpool_postgres::{PoolError, Manager, Runtime};
use rocket::async_trait;
use rocket::serde::Deserialize;
use std::time::Duration;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::crypto::{CryptoProvider, verify_tls12_signature, verify_tls13_signature, WebPkiSupportedAlgorithms};
use rustls::client::danger;
use rustls::client::verify_server_cert_signed_by_trust_anchor;
use rustls::server::ParsedCertificate;
use rustls::{DigitallySignedStruct, SignatureScheme, RootCertStore};
use std::sync::Arc;
use std::path::PathBuf;

#[derive(Deserialize, Copy, Clone)]
#[serde(crate = "rocket::serde")]
#[serde(rename_all="kebab-case")]
pub enum VerifyMode{
    NoVerify,
    VerifyCa,
    VerifyFull,
}

#[derive(Debug)]
struct NoVerification;
impl danger::ServerCertVerifier for NoVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer,
        _intermediates: &[CertificateDer],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> std::result::Result<danger::ServerCertVerified, rustls::Error> {
        Ok(danger::ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct
    ) -> Result<danger::HandshakeSignatureValid, rustls::Error> {
        Ok(danger::HandshakeSignatureValid::assertion())
    }
    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct
    ) -> Result<danger::HandshakeSignatureValid, rustls::Error> {
        Ok(danger::HandshakeSignatureValid::assertion())
    }
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> { Vec::new() }
}
#[derive(Debug)]
struct CaVerification(WebPkiSupportedAlgorithms, Arc<RootCertStore>);
impl CaVerification{
    fn new(ca: RootCertStore) -> Self {
        let roots = Arc::new(ca);
        let provider = CryptoProvider::get_default().unwrap();
        Self(provider.signature_verification_algorithms.clone(), roots)
    }
}
impl danger::ServerCertVerifier for CaVerification {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer,
        intermediates: &[CertificateDer],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        now: UnixTime,
    ) -> std::result::Result<danger::ServerCertVerified, rustls::Error> {
        verify_server_cert_signed_by_trust_anchor(
            &ParsedCertificate::try_from(end_entity)?,
            &self.1,
            intermediates,
            now,
            self.0.all
        )?;
        Ok(danger::ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct
    ) -> Result<danger::HandshakeSignatureValid, rustls::Error> {
        verify_tls12_signature(message, cert, dss, &self.0)
    }
    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct
    ) -> Result<danger::HandshakeSignatureValid, rustls::Error> {
        verify_tls13_signature(message, cert, dss, &self.0)
    }
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.0.supported_schemes()
    }
}

///A pool which supports TLS for postgres connections
///Due to the way the config system works, there's a separate sslmode config variable.
///The sslmode in the connection url has three modes: disable, prefer, require.
///The verification level has three modes: no-verify, verify-ca, verify-full.
///The root CA can be provided either as the ca config parameter or in ~/.postgresql/root.crt
///
///Not yet implemented:
///- Client Certificates
///- CRL checking
///- `system` root-ca
///
///Example:
///```toml
///[default.databases.main]
///url = "postgresql://user@host.example/dbname?sslmode=require"
///verify-mode = "verify-ca"
///root-ca = "./postgres-ca.pem"
///```
pub struct TlsPool(deadpool_postgres::Pool);

#[async_trait]
impl rocket_db_pools::Pool for TlsPool{
    type Error = rocket_db_pools::Error<PoolError>;

    type Connection = deadpool_postgres::Object;

    async fn init(figment: &Figment) -> Result<Self, Self::Error> {
        let config: Config = figment.extract()?;
        let verify_mode: VerifyMode = figment.extract_inner("verify-mode")?;//.unwrap_or(VerifyMode::NoVerify);
        let ca: Option<String> = figment.extract_inner("root-ca")?;
        let mut roots = RootCertStore::empty();
        match ca {
            Some(ca) => {
                let data = tokio::fs::read(&ca).await.unwrap(); //TODO: better error handling
                roots.add(CertificateDer::from_slice(&data)).unwrap(); //TODO: better error handling
            }
            None => {
                //Get the home directory but default to /var/lib/pgsql which is mentioned as a common location for postgres installation
                #[allow(deprecated)]
                let mut filename = std::env::home_dir().unwrap_or_else(||PathBuf::from("/var/lib/pgsql"));
                filename.push(".postgresql/root.crt");
                if let Ok(data) = tokio::fs::read(&filename).await{
                    roots.add(CertificateDer::from_slice(&data)).unwrap() //TODO: error handling
                }
            }
        }
        let tls_config: rustls::ClientConfig = match verify_mode{
            VerifyMode::VerifyFull => {
                rustls::ClientConfig::builder()
                    .with_root_certificates(roots)
                    .with_no_client_auth()
            }
            VerifyMode::VerifyCa => {
                rustls::ClientConfig::builder()
                    .dangerous()
                    .with_custom_certificate_verifier(Arc::new(CaVerification::new(roots)))
                    .with_no_client_auth()
            }
            VerifyMode::NoVerify => {
                rustls::ClientConfig::builder()
                    .dangerous()
                    .with_custom_certificate_verifier(Arc::new(NoVerification))
                    .with_no_client_auth()
            }
        };
        let tls = tokio_postgres_rustls::MakeRustlsConnect::new(tls_config);
        let manager = Manager::new(config.url.parse().map_err(|e|Error::Init(PoolError::Backend(e)))?, tls);

        Ok(Self(deadpool_postgres::Pool::builder(manager)
            .max_size(config.max_connections)
            .wait_timeout(Some(Duration::from_secs(config.connect_timeout)))
            .create_timeout(Some(Duration::from_secs(config.connect_timeout)))
            .recycle_timeout(config.idle_timeout.map(Duration::from_secs))
            .runtime(Runtime::Tokio1)
            .build()
            .map_err(|_| Error::Init(PoolError::NoRuntimeSpecified))?))
    }

    async fn get(&self) -> Result<Self::Connection, Self::Error> {
        self.0.get().await.map_err(Error::Get)
    }

    async fn close(&self) {
        self.0.close()
    }
}
