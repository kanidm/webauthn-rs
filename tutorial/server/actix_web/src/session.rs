use std::ops::Add;
use std::sync::Mutex;
use std::{collections::HashMap, sync::LazyLock};

use actix_session::storage::{LoadError, SaveError, SessionKey, SessionStore, UpdateError};
use actix_web::cookie::time::Duration;
use anyhow::anyhow;
use chrono::Utc;
use rand::distributions::{Alphanumeric, DistString};

/**
Static map where session states are stored
*/
static SESSION_STATES: LazyLock<Mutex<HashMap<String, State>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

pub(crate) struct State {
    session_state: HashMap<String, String>,
    valid_until: chrono::DateTime<Utc>,
}

/**
Implementation of the [SessionStore] trait of [actix_session].
*/
#[derive(Default)]
pub(crate) struct MemorySession;

impl SessionStore for MemorySession {
    async fn load(
        &self,
        session_key: &SessionKey,
    ) -> Result<Option<HashMap<String, String>>, LoadError> {
        let now = Utc::now();

        Ok(SESSION_STATES
            .lock()
            .map_err(|_| LoadError::Other(anyhow!("Poison Error")))?
            .get(session_key.as_ref())
            .filter(|&v| v.valid_until >= now)
            .map(|state| state.session_state.clone()))
    }

    async fn save(
        &self,
        session_state: HashMap<String, String>,
        ttl: &Duration,
    ) -> Result<SessionKey, SaveError> {
        let mut session_key;

        loop {
            session_key = Alphanumeric.sample_string(&mut rand::thread_rng(), 512);

            if !SESSION_STATES
                .lock()
                .map_err(|_| SaveError::Other(anyhow!("Poison Error")))?
                .contains_key(&session_key)
            {
                break;
            }
        }

        SESSION_STATES
            .lock()
            .map_err(|_| SaveError::Other(anyhow!("Poison Error")))?
            .insert(
                session_key.clone(),
                State {
                    session_state,
                    valid_until: Utc::now()
                        .add(chrono::Duration::nanoseconds(ttl.whole_nanoseconds() as i64)),
                },
            );

        SessionKey::try_from(session_key)
            .map_err(|_| SaveError::Serialization(anyhow!("Invalid Session Key Error")))
    }

    async fn update(
        &self,
        session_key: SessionKey,
        session_state: HashMap<String, String>,
        ttl: &Duration,
    ) -> Result<SessionKey, UpdateError> {
        if let Some(entry) = SESSION_STATES
            .lock()
            .map_err(|_| UpdateError::Other(anyhow!("Poison Error")))?
            .get_mut(session_key.as_ref())
        {
            entry.valid_until =
                Utc::now().add(chrono::Duration::nanoseconds(ttl.whole_nanoseconds() as i64));
            entry.session_state = session_state;

            Ok(session_key)
        } else {
            Err(UpdateError::Other(anyhow!(
                "Didn't found session with that key"
            )))
        }
    }

    async fn update_ttl(
        &self,
        session_key: &SessionKey,
        ttl: &Duration,
    ) -> Result<(), anyhow::Error> {
        if let Some(entry) = SESSION_STATES
            .lock()
            .map_err(|_| anyhow!("Poison Error"))?
            .get_mut(session_key.as_ref())
        {
            entry.valid_until =
                Utc::now().add(chrono::Duration::nanoseconds(ttl.whole_nanoseconds() as i64));
        }

        Ok(())
    }

    async fn delete(&self, session_key: &SessionKey) -> Result<(), anyhow::Error> {
        SESSION_STATES
            .lock()
            .map_err(|_| anyhow!("Poison Error"))?
            .remove(session_key.as_ref());

        Ok(())
    }
}
