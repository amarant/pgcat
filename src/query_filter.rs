use bytes::{Buf, BytesMut};
use std::collections::HashSet;
use log::{error, trace};
use crate::config::QueryFilterConfig;
use crate::errors::Error;
use pg_query::Result as PgQueryResult;
use std::fs::{File, OpenOptions};
use std::io::Write;

pub struct QueryLogger {
    file_path: String,
    file: File,
    set: HashSet<u64>,
    normalized: bool,
}

fn open_file(f: &str) -> Result<File, Error> {
    let file = OpenOptions::new()
        .write(true)
        .append(true)
        .create(true)
        .open(f)
        .map_err(|err| {
            error!("Error with logging file {:?} {:?}", f, err);
            Error::BadConfig
        });
    file
}

impl QueryLogger {
    fn new(file_path: &str, normalized: bool) -> Result<QueryLogger, Error> {
        let file = open_file(file_path)?;
        Ok(QueryLogger{
            file_path: file_path.to_string(),
            file,
            set: HashSet::default(),
            normalized
        })
    }

    fn log_query(&mut self, query: &str) {
        let query = if self.normalized {
            let norm_res = pg_query::normalize(query);
            match norm_res {
                Err(err) => {
                    error ! ("Can't normalize query {} with error {:?}", &query, err);
                    query.to_string()
                },
                Ok(norm) => norm,
            }
        } else {
            query.to_string()
        };
        let log_query = match pg_query::fingerprint(&query) {
            Err(err) => {
                error!("Can't fingerprint query {} with error {:?}", &query, err);
                true
            },
            Ok(f) => self.set.insert(f.value),
        };
        if log_query {
            if let Err(err) = writeln!(self.file, "{}", &query) {
                error!("Can't log in file {} query {} with error {:?}", &self.file_path, &query, err);
            }
        }
    }
}

pub struct QueryFilter {
    allowed_set: Option<HashSet<u64>>,
    log_censored: Option<QueryLogger>,
    log_allowed: Option<QueryLogger>,
}

fn get_normalized_fingerprint(query: &str) -> PgQueryResult<u64> {
    // let normalized = pg_query::normalize(&query)?;
    // trace!("query normalized {}", normalized);
    let fingerprint = pg_query::fingerprint(&query)?;
    trace!("query fingerprint {}", fingerprint.hex);
    Ok(fingerprint.value)
}

fn map_pg_err<E>(pg_res: PgQueryResult<E>) -> Result<E, Error> {
    return match pg_res {
        Ok(allowed_set) => Ok(allowed_set),
        Err(pg_err) => {
            error!("Error when parsing query {:?}", pg_err);
            Err(Error::BadConfig)
        }
    };
}


impl QueryFilter {
    pub fn new(conf: QueryFilterConfig) -> Result<QueryFilter, Error> {
        trace!("Query filter configuration {:?}", conf);
        let allowed_set_res = conf.allowed_queries
            .map(|a| a
                .iter()
                .map(|query| get_normalized_fingerprint(query))
                .collect::<PgQueryResult<HashSet<u64>>>())
            .transpose();

        let allowed_set = map_pg_err(allowed_set_res)?;

        let log_censored = conf.log_censored
            .map(|l| QueryLogger::new(&l.file, l.normalized.unwrap_or(true)))
            .transpose()?;
        let log_allowed = conf.log_allowed
            .map(|l| QueryLogger::new(&l.file, l.normalized.unwrap_or(true)))
            .transpose()?;

        Ok(QueryFilter{
            allowed_set,
            log_censored,
            log_allowed,
        })
    }

    pub fn allow(&mut self, mut buf: BytesMut) -> bool {
        let code = buf.get_u8() as char;

        // Only simple protocol supported for commands.
        if code != 'Q' {
            return false;
        }

        let len = buf.get_i32() as usize;
        let query = String::from_utf8_lossy(&buf[..len - 5])
            .replace("\r\n", " ")
            .replace('\n', " "); // Ignore the terminating NULL.
        trace!("query to filter {}", query);
        let pg_res = get_normalized_fingerprint(&query);
        let allow_res = map_pg_err(pg_res)
            .map(|fingerprint_value| self.allowed_set.as_ref()
                .map_or( true, |a| a.contains(&fingerprint_value)));
        let allow = allow_res.unwrap_or(false);
        if allow {
            if let Some(log) = &mut self.log_allowed {
                log.log_query(&query)
            }
        } else {
            if let Some(log) = &mut self.log_censored {
                log.log_query(&query)
            }
        }
        allow
    }
}