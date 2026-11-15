//! Connected peer sessions used to coordinate snapshot votes.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{self, Receiver, SyncSender};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Instant;

use vess_core::Hash;

pub struct Query {
    pub height: u64,
    pub deadline: Instant,
    pub peer: Hash,
    pub reply: mpsc::Sender<(Hash, Option<Hash>)>,
}

struct Entry {
    key: Hash,
    sender: SyncSender<Query>,
}

#[derive(Default)]
struct Registry {
    generation: u64,
    sessions: HashMap<u64, Entry>,
}

#[derive(Default)]
pub struct PeerSessions {
    registry: Mutex<Registry>,
    next_id: AtomicU64,
    attempt: Mutex<()>,
}

pub struct Session {
    registry: Arc<PeerSessions>,
    id: u64,
    pub key: Hash,
    pub requests: Receiver<Query>,
}

pub struct Voters {
    pub generation: u64,
    pub peers: HashMap<Hash, SyncSender<Query>>,
}

impl PeerSessions {
    pub fn register(self: &Arc<Self>, key: Hash) -> Session {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let (sender, requests) = mpsc::sync_channel(1);
        let mut registry = self.registry.lock().unwrap_or_else(|e| e.into_inner());
        registry.sessions.insert(id, Entry { key, sender });
        registry.generation = registry.generation.wrapping_add(1);
        Session {
            registry: self.clone(),
            id,
            key,
            requests,
        }
    }

    pub fn try_attempt(&self) -> Option<MutexGuard<'_, ()>> {
        match self.attempt.try_lock() {
            Ok(guard) => Some(guard),
            Err(std::sync::TryLockError::WouldBlock) => None,
            Err(std::sync::TryLockError::Poisoned(error)) => Some(error.into_inner()),
        }
    }

    pub fn voters(&self, source: &Session) -> Option<Voters> {
        let registry = self.registry.lock().unwrap_or_else(|e| e.into_inner());
        if !registry.sessions.contains_key(&source.id) {
            return None;
        }
        let mut peers = HashMap::new();
        for entry in registry.sessions.values() {
            peers
                .entry(entry.key)
                .or_insert_with(|| entry.sender.clone());
        }
        Some(Voters {
            generation: registry.generation,
            peers,
        })
    }

    pub fn with_unchanged<R>(&self, generation: u64, apply: impl FnOnce() -> R) -> Option<R> {
        let registry = self.registry.lock().unwrap_or_else(|e| e.into_inner());
        if registry.generation != generation {
            return None;
        }
        Some(apply())
    }

    #[cfg(test)]
    pub fn peer_count(&self) -> usize {
        let registry = self.registry.lock().unwrap_or_else(|e| e.into_inner());
        registry
            .sessions
            .values()
            .map(|entry| entry.key)
            .collect::<std::collections::HashSet<_>>()
            .len()
    }

    #[cfg(test)]
    pub fn session_count(&self) -> usize {
        self.registry
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .sessions
            .len()
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        let mut registry = self
            .registry
            .registry
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        registry.sessions.remove(&self.id);
        registry.generation = registry.generation.wrapping_add(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn voters_are_unique_identities_and_membership_changes_invalidate_a_vote() {
        let sessions = Arc::new(PeerSessions::default());
        let first = sessions.register([1; 32]);
        let duplicate = sessions.register([1; 32]);
        let second = sessions.register([2; 32]);
        let voters = sessions.voters(&first).unwrap();
        assert_eq!(voters.peers.len(), 2);
        assert_eq!(sessions.with_unchanged(voters.generation, || 7), Some(7));
        drop(duplicate);
        let mut installed = false;
        assert_eq!(
            sessions.with_unchanged(voters.generation, || installed = true),
            None
        );
        assert!(!installed);
        let voters = sessions.voters(&first).unwrap();
        drop(second);
        assert_eq!(sessions.with_unchanged(voters.generation, || 7), None);
    }

    #[test]
    fn only_one_snapshot_attempt_runs_at_a_time() {
        let sessions = PeerSessions::default();
        let attempt = sessions.try_attempt().unwrap();
        assert!(sessions.try_attempt().is_none());
        drop(attempt);
        assert!(sessions.try_attempt().is_some());
    }
}
