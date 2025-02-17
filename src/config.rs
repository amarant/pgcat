/// Parse the configuration file.
use arc_swap::ArcSwap;
use log::{error, info};
use once_cell::sync::Lazy;
use serde_derive::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::hash::Hash;
use std::path::Path;
use std::sync::Arc;
use tokio::fs::File;
use tokio::io::AsyncReadExt;
use toml;

use crate::errors::Error;
use crate::tls::{load_certs, load_keys};
use crate::{ClientServerMap, ConnectionPool};

pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Globally available configuration.
static CONFIG: Lazy<ArcSwap<Config>> = Lazy::new(|| ArcSwap::from_pointee(Config::default()));

/// Server role: primary or replica.
#[derive(Clone, PartialEq, Serialize, Deserialize, Hash, std::cmp::Eq, Debug, Copy)]
pub enum Role {
    Primary,
    Replica,
}

impl ToString for Role {
    fn to_string(&self) -> String {
        match *self {
            Role::Primary => "primary".to_string(),
            Role::Replica => "replica".to_string(),
        }
    }
}

impl PartialEq<Option<Role>> for Role {
    fn eq(&self, other: &Option<Role>) -> bool {
        match other {
            None => true,
            Some(role) => *self == *role,
        }
    }
}

impl PartialEq<Role> for Option<Role> {
    fn eq(&self, other: &Role) -> bool {
        match *self {
            None => true,
            Some(role) => role == *other,
        }
    }
}

/// Address identifying a PostgreSQL server uniquely.
#[derive(Clone, PartialEq, Hash, std::cmp::Eq, Debug)]
pub struct Address {
    /// Unique ID per addressable Postgres server.
    pub id: usize,

    /// Server host.
    pub host: String,

    /// Server port.
    pub port: u16,

    /// Shard number of this Postgres server.
    pub shard: usize,

    /// The name of the Postgres database.
    pub database: String,

    /// Server role: replica, primary.
    pub role: Role,

    /// If it's a replica, number it for reference and failover.
    pub replica_number: usize,

    /// Position of the server in the pool for failover.
    pub address_index: usize,

    /// The name of the user configured to use this pool.
    pub username: String,

    /// The name of this pool (i.e. database name visible to the client).
    pub pool_name: String,
}

impl Default for Address {
    fn default() -> Address {
        Address {
            id: 0,
            host: String::from("127.0.0.1"),
            port: 5432,
            shard: 0,
            address_index: 0,
            replica_number: 0,
            database: String::from("database"),
            role: Role::Replica,
            username: String::from("username"),
            pool_name: String::from("pool_name"),
        }
    }
}

impl Address {
    /// Address name (aka database) used in `SHOW STATS`, `SHOW DATABASES`, and `SHOW POOLS`.
    pub fn name(&self) -> String {
        match self.role {
            Role::Primary => format!("{}_shard_{}_primary", self.pool_name, self.shard),

            Role::Replica => format!(
                "{}_shard_{}_replica_{}",
                self.pool_name, self.shard, self.replica_number
            ),
        }
    }
}

/// PostgreSQL user.
#[derive(Clone, PartialEq, Hash, std::cmp::Eq, Serialize, Deserialize, Debug)]
pub struct User {
    pub username: String,
    pub password: String,
    pub pool_size: u32,
    pub statement_timeout: u64,
}

impl Default for User {
    fn default() -> User {
        User {
            username: String::from("postgres"),
            password: String::new(),
            pool_size: 15,
            statement_timeout: 0,
        }
    }
}

/// General configuration.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct General {
    pub host: String,
    pub port: i16,
    pub enable_prometheus_exporter: Option<bool>,
    pub prometheus_exporter_port: i16,
    pub connect_timeout: u64,
    pub healthcheck_timeout: u64,
    pub shutdown_timeout: u64,
    pub healthcheck_delay: u64,
    pub ban_time: i64,
    pub autoreload: bool,
    pub tls_certificate: Option<String>,
    pub tls_private_key: Option<String>,
    pub admin_username: String,
    pub admin_password: String,
}

impl Default for General {
    fn default() -> General {
        General {
            host: String::from("localhost"),
            port: 5432,
            enable_prometheus_exporter: Some(false),
            prometheus_exporter_port: 9930,
            connect_timeout: 5000,
            healthcheck_timeout: 1000,
            shutdown_timeout: 60000,
            healthcheck_delay: 30000,
            ban_time: 60,
            autoreload: false,
            tls_certificate: None,
            tls_private_key: None,
            admin_username: String::from("admin"),
            admin_password: String::from("admin"),
        }
    }
}
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct Pool {
    pub pool_mode: String,
    pub default_role: String,
    pub query_parser_enabled: bool,
    pub primary_reads_enabled: bool,
    pub sharding_function: String,
    pub shards: HashMap<String, Shard>,
    pub users: HashMap<String, User>,
}
impl Default for Pool {
    fn default() -> Pool {
        Pool {
            pool_mode: String::from("transaction"),
            shards: HashMap::from([(String::from("1"), Shard::default())]),
            users: HashMap::default(),
            default_role: String::from("any"),
            query_parser_enabled: false,
            primary_reads_enabled: true,
            sharding_function: "pg_bigint_hash".to_string(),
        }
    }
}

/// Shard configuration.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct Shard {
    pub database: String,
    pub servers: Vec<(String, u16, String)>,
}

impl Default for Shard {
    fn default() -> Shard {
        Shard {
            servers: vec![(String::from("localhost"), 5432, String::from("primary"))],
            database: String::from("postgres"),
        }
    }
}

fn default_path() -> String {
    String::from("pgcat.toml")
}

/// Configuration wrapper.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct Config {
    // Serializer maintains the order of fields in the struct
    // so we should always put simple fields before nested fields
    // in all serializable structs to avoid ValueAfterTable errors
    // These errors occur when the toml serializer is about to produce
    // ambigous toml structure like the one below
    // [main]
    // field1_under_main = 1
    // field2_under_main = 2
    // [main.subconf]
    // field1_under_subconf = 1
    // field3_under_main = 3 # This field will be interpreted as being under subconf and not under main
    #[serde(default = "default_path")]
    pub path: String,

    pub general: General,
    pub pools: HashMap<String, Pool>,
}

impl Default for Config {
    fn default() -> Config {
        Config {
            path: String::from("pgcat.toml"),
            general: General::default(),
            pools: HashMap::default(),
        }
    }
}

impl From<&Config> for std::collections::HashMap<String, String> {
    fn from(config: &Config) -> HashMap<String, String> {
        let mut r: Vec<(String, String)> = config
            .pools
            .iter()
            .flat_map(|(pool_name, pool)| {
                [
                    (
                        format!("pools.{}.pool_mode", pool_name),
                        pool.pool_mode.clone(),
                    ),
                    (
                        format!("pools.{}.primary_reads_enabled", pool_name),
                        pool.primary_reads_enabled.to_string(),
                    ),
                    (
                        format!("pools.{}.query_parser_enabled", pool_name),
                        pool.query_parser_enabled.to_string(),
                    ),
                    (
                        format!("pools.{}.default_role", pool_name),
                        pool.default_role.clone(),
                    ),
                    (
                        format!("pools.{}.sharding_function", pool_name),
                        pool.sharding_function.clone(),
                    ),
                    (
                        format!("pools.{:?}.shard_count", pool_name),
                        pool.shards.len().to_string(),
                    ),
                    (
                        format!("pools.{:?}.users", pool_name),
                        pool.users
                            .iter()
                            .map(|(_username, user)| &user.username)
                            .cloned()
                            .collect::<Vec<String>>()
                            .join(", "),
                    ),
                ]
            })
            .collect();

        let mut static_settings = vec![
            ("host".to_string(), config.general.host.to_string()),
            ("port".to_string(), config.general.port.to_string()),
            (
                "prometheus_exporter_port".to_string(),
                config.general.prometheus_exporter_port.to_string(),
            ),
            (
                "connect_timeout".to_string(),
                config.general.connect_timeout.to_string(),
            ),
            (
                "healthcheck_timeout".to_string(),
                config.general.healthcheck_timeout.to_string(),
            ),
            (
                "shutdown_timeout".to_string(),
                config.general.shutdown_timeout.to_string(),
            ),
            (
                "healthcheck_delay".to_string(),
                config.general.healthcheck_delay.to_string(),
            ),
            ("ban_time".to_string(), config.general.ban_time.to_string()),
        ];

        r.append(&mut static_settings);
        return r.iter().cloned().collect();
    }
}

impl Config {
    /// Print current configuration.
    pub fn show(&self) {
        info!("Ban time: {}s", self.general.ban_time);
        info!(
            "Healthcheck timeout: {}ms",
            self.general.healthcheck_timeout
        );
        info!("Connection timeout: {}ms", self.general.connect_timeout);
        info!("Shutdown timeout: {}ms", self.general.shutdown_timeout);
        info!("Healthcheck delay: {}ms", self.general.healthcheck_delay);
        match self.general.tls_certificate.clone() {
            Some(tls_certificate) => {
                info!("TLS certificate: {}", tls_certificate);

                match self.general.tls_private_key.clone() {
                    Some(tls_private_key) => {
                        info!("TLS private key: {}", tls_private_key);
                        info!("TLS support is enabled");
                    }

                    None => (),
                }
            }

            None => {
                info!("TLS support is disabled");
            }
        };

        for (pool_name, pool_config) in &self.pools {
            // TODO: Make this output prettier (maybe a table?)
            info!(
                "[pool: {}] Maximum user connections: {}",
                pool_name,
                pool_config
                    .users
                    .iter()
                    .map(|(_, user_cfg)| user_cfg.pool_size)
                    .sum::<u32>()
                    .to_string()
            );
            info!("[pool: {}] Pool mode: {}", pool_name, pool_config.pool_mode);
            info!(
                "[pool: {}] Sharding function: {}",
                pool_name, pool_config.sharding_function
            );
            info!(
                "[pool: {}] Primary reads: {}",
                pool_name, pool_config.primary_reads_enabled
            );
            info!(
                "[pool: {}] Query router: {}",
                pool_name, pool_config.query_parser_enabled
            );
            info!(
                "[pool: {}] Number of shards: {}",
                pool_name,
                pool_config.shards.len()
            );
            info!(
                "[pool: {}] Number of users: {}",
                pool_name,
                pool_config.users.len()
            );

            for user in &pool_config.users {
                info!(
                    "[pool: {}][user: {}] Pool size: {}",
                    pool_name, user.1.username, user.1.pool_size,
                );
                info!(
                    "[pool: {}][user: {}] Statement timeout: {}",
                    pool_name, user.1.username, user.1.statement_timeout
                )
            }
        }
    }
}

/// Get a read-only instance of the configuration
/// from anywhere in the app.
/// ArcSwap makes this cheap and quick.
pub fn get_config() -> Config {
    (*(*CONFIG.load())).clone()
}

/// Parse the configuration file located at the path.
pub async fn parse(path: &str) -> Result<(), Error> {
    let mut contents = String::new();
    let mut file = match File::open(path).await {
        Ok(file) => file,
        Err(err) => {
            error!("Could not open '{}': {}", path, err.to_string());
            return Err(Error::BadConfig);
        }
    };

    match file.read_to_string(&mut contents).await {
        Ok(_) => (),
        Err(err) => {
            error!("Could not read config file: {}", err.to_string());
            return Err(Error::BadConfig);
        }
    };

    let mut config: Config = match toml::from_str(&contents) {
        Ok(config) => config,
        Err(err) => {
            error!("Could not parse config file: {}", err.to_string());
            return Err(Error::BadConfig);
        }
    };

    // Validate TLS!
    match config.general.tls_certificate.clone() {
        Some(tls_certificate) => {
            match load_certs(&Path::new(&tls_certificate)) {
                Ok(_) => {
                    // Cert is okay, but what about the private key?
                    match config.general.tls_private_key.clone() {
                        Some(tls_private_key) => match load_keys(&Path::new(&tls_private_key)) {
                            Ok(_) => (),
                            Err(err) => {
                                error!("tls_private_key is incorrectly configured: {:?}", err);
                                return Err(Error::BadConfig);
                            }
                        },

                        None => {
                            error!("tls_certificate is set, but the tls_private_key is not");
                            return Err(Error::BadConfig);
                        }
                    };
                }

                Err(err) => {
                    error!("tls_certificate is incorrectly configured: {:?}", err);
                    return Err(Error::BadConfig);
                }
            }
        }
        None => (),
    };

    for (pool_name, pool) in &config.pools {
        match pool.sharding_function.as_ref() {
            "pg_bigint_hash" => (),
            "sha1" => (),
            _ => {
                error!(
                    "Supported sharding functions are: 'pg_bigint_hash', 'sha1', got: '{}' in pool {} settings",
                    pool.sharding_function,
                    pool_name
                );
                return Err(Error::BadConfig);
            }
        };

        match pool.default_role.as_ref() {
            "any" => (),
            "primary" => (),
            "replica" => (),
            other => {
                error!(
                    "Query router default_role must be 'primary', 'replica', or 'any', got: '{}'",
                    other
                );
                return Err(Error::BadConfig);
            }
        };

        match pool.pool_mode.as_ref() {
            "transaction" => (),
            "session" => (),
            other => {
                error!(
                    "pool_mode can be 'session' or 'transaction', got: '{}'",
                    other
                );
                return Err(Error::BadConfig);
            }
        };

        for shard in &pool.shards {
            // We use addresses as unique identifiers,
            // let's make sure they are unique in the config as well.
            let mut dup_check = HashSet::new();
            let mut primary_count = 0;

            match shard.0.parse::<usize>() {
                Ok(_) => (),
                Err(_) => {
                    error!(
                        "Shard '{}' is not a valid number, shards must be numbered starting at 0",
                        shard.0
                    );
                    return Err(Error::BadConfig);
                }
            };

            if shard.1.servers.len() == 0 {
                error!("Shard {} has no servers configured", shard.0);
                return Err(Error::BadConfig);
            }

            for server in &shard.1.servers {
                dup_check.insert(server);

                // Check that we define only zero or one primary.
                match server.2.as_ref() {
                    "primary" => primary_count += 1,
                    _ => (),
                };

                // Check role spelling.
                match server.2.as_ref() {
                    "primary" => (),
                    "replica" => (),
                    _ => {
                        error!(
                            "Shard {} server role must be either 'primary' or 'replica', got: '{}'",
                            shard.0, server.2
                        );
                        return Err(Error::BadConfig);
                    }
                };
            }

            if primary_count > 1 {
                error!("Shard {} has more than on primary configured", &shard.0);
                return Err(Error::BadConfig);
            }

            if dup_check.len() != shard.1.servers.len() {
                error!("Shard {} contains duplicate server configs", &shard.0);
                return Err(Error::BadConfig);
            }
        }
    }

    config.path = path.to_string();

    // Update the configuration globally.
    CONFIG.store(Arc::new(config.clone()));

    Ok(())
}

pub async fn reload_config(client_server_map: ClientServerMap) -> Result<bool, Error> {
    let old_config = get_config();
    match parse(&old_config.path).await {
        Ok(()) => (),
        Err(err) => {
            error!("Config reload error: {:?}", err);
            return Err(Error::BadConfig);
        }
    };
    let new_config = get_config();

    if old_config.pools != new_config.pools {
        info!("Pool configuration changed, re-creating server pools");
        ConnectionPool::from_config(client_server_map).await?;
        Ok(true)
    } else if old_config != new_config {
        Ok(true)
    } else {
        Ok(false)
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[tokio::test]
    async fn test_config() {
        parse("pgcat.toml").await.unwrap();

        assert_eq!(get_config().path, "pgcat.toml".to_string());

        assert_eq!(get_config().general.ban_time, 60);
        assert_eq!(get_config().pools.len(), 2);
        assert_eq!(get_config().pools["sharded_db"].shards.len(), 3);
        assert_eq!(get_config().pools["simple_db"].shards.len(), 1);
        assert_eq!(get_config().pools["sharded_db"].users.len(), 2);
        assert_eq!(get_config().pools["simple_db"].users.len(), 1);

        assert_eq!(
            get_config().pools["sharded_db"].shards["0"].servers[0].0,
            "127.0.0.1"
        );
        assert_eq!(
            get_config().pools["sharded_db"].shards["1"].servers[0].2,
            "primary"
        );
        assert_eq!(
            get_config().pools["sharded_db"].shards["1"].database,
            "shard1"
        );
        assert_eq!(
            get_config().pools["sharded_db"].users["0"].username,
            "sharding_user"
        );
        assert_eq!(
            get_config().pools["sharded_db"].users["1"].password,
            "other_user"
        );
        assert_eq!(get_config().pools["sharded_db"].users["1"].pool_size, 21);
        assert_eq!(get_config().pools["sharded_db"].default_role, "any");

        assert_eq!(
            get_config().pools["simple_db"].shards["0"].servers[0].0,
            "127.0.0.1"
        );
        assert_eq!(
            get_config().pools["simple_db"].shards["0"].servers[0].1,
            5432
        );
        assert_eq!(
            get_config().pools["simple_db"].shards["0"].database,
            "some_db"
        );
        assert_eq!(get_config().pools["simple_db"].default_role, "primary");

        assert_eq!(
            get_config().pools["simple_db"].users["0"].username,
            "simple_user"
        );
        assert_eq!(
            get_config().pools["simple_db"].users["0"].password,
            "simple_user"
        );
        assert_eq!(get_config().pools["simple_db"].users["0"].pool_size, 5);
    }

    #[tokio::test]
    async fn test_serialize_configs() {
        parse("pgcat.toml").await.unwrap();
        print!("{}", toml::to_string(&get_config()).unwrap());
    }
}
