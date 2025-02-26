use super::{header::CoValueHeader, session::SessionLog};
use crate::{
    id::{rawcoid::RawCoID, session_id::SessionID},
    sync::common::CoValueKnownState,
};
use dashmap::DashMap;
use rayon::iter::ParallelIterator;

pub struct CoValueCore {
    id: RawCoID,
    header: CoValueHeader,
    session_logs: DashMap<SessionID, SessionLog>,
    cached_known_state: Option<CoValueKnownState>,
}

impl CoValueCore {
    pub fn known_state_uncached(&self) -> CoValueKnownState {
        CoValueKnownState {
            id: self.id.clone(),
            header: true,
            sessions: self
                .session_logs
                .par_iter_mut()
                .map(|x| (x.key().clone(), x.value().transactions.len()))
                .collect(),
        }
    }

    pub fn known_state(&mut self) -> CoValueKnownState {
        match &self.cached_known_state {
            Some(known_state) => known_state.clone(),
            None => {
                let known_state = self.known_state_uncached();
                self.cached_known_state = Some(known_state.clone());
                known_state
            }
        }
    }

    pub fn meta(&self) -> Option<serde_json::Value> {
        self.header.meta.clone()
    }
}
