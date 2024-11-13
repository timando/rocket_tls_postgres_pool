use rocket::figment::Figment;
use rocket::tokio;
use rocket_db_pools::{deadpool_postgres, Error, Config};
use deadpool_postgres::{PoolError, Manager, Runtime};
use rocket::async_trait;
use std::time::Duration;
use std::path::PathBuf;
use crate::VerifyMode;
use native_tls::{Certificate, TlsConnector};

///A pool which supports TLS for postgres connections using native-tls
///Due to the way the config system works, there's a separate sslmode config variable.
///The sslmode in the connection url has three modes: disable, prefer, require.
///The verification level has three modes: no-verify (default), verify-ca, verify-full.
///The root CA can be provided either as the ca config parameter or in ~/.postgresql/root.crt
///
///Not yet implemented:
///- Client Certificates
///- CRL checking
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
        let verify_mode: VerifyMode = figment.extract_inner("verify-mode").or_else(|e|if e.missing(){Ok(VerifyMode::NoVerify)} else {Err(e)})?;
        let ca: Option<String> = figment.extract_inner("root-ca").ok();

        let mut builder = TlsConnector::builder();
        match ca.as_deref() {
            Some(ca) if ca == "system" => {
                builder.disable_built_in_roots(false);
            }
            Some(ca) => {
                let data = tokio::fs::read(ca).await.unwrap(); //TODO: better error handling
                let cert = Certificate::from_pem(&data).unwrap(); //TODO: error handling
                builder.disable_built_in_roots(true);
                builder.add_root_certificate(cert);
            }
            None => {
                builder.disable_built_in_roots(true);
                //Get the home directory but default to /var/lib/pgsql which is mentioned as a common location for postgres installation
                #[allow(deprecated)]
                let mut filename = std::env::home_dir().unwrap_or_else(||PathBuf::from("/var/lib/pgsql"));
                filename.push(".postgresql/root.crt");
                if let Ok(data) = tokio::fs::read(&filename).await{
                    let cert = Certificate::from_pem(&data).unwrap(); //TODO: error handling
                    builder.add_root_certificate(cert);
                }
            }
        }
        match verify_mode{
            VerifyMode::VerifyFull => (),
            VerifyMode::VerifyCa => {
                if ca.as_deref() == Some("system") {
                    log::warn!("system CA used with verify-ca verification mode. This is insecure. Using verify-full instead.");
                    builder.danger_accept_invalid_hostnames(false);
                } else {
                    builder.danger_accept_invalid_hostnames(true);
                }

            }
            VerifyMode::NoVerify => {
                builder.danger_accept_invalid_certs(true);
            }
        };
        let tls = postgres_native_tls::MakeTlsConnector::new(builder.build().unwrap());//TODO: error handling
        let manager = Manager::new(dbg!(config.url.parse()).map_err(|e|Error::Init(PoolError::Backend(e)))?, tls);

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
