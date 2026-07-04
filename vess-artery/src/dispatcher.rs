use std::sync::{Arc, Mutex};
use vess_protocol::PulseMessage;
use vess_foundry::Vess;
use crate::node_runner::{NodeState, validate_vess};

pub fn handle_vess_submit(state: &Arc<Mutex<NodeState>>, v: &Vess) -> bool {
    let valid = {
        let s = state.lock().unwrap();
        validate_vess(v, &s.store, s.current_epoch).is_ok()
    };
    if valid {
        let mut s = state.lock().unwrap();
        let id = v.compute_vess_id();
        s.store.upsert(v);
        tracing::info!(id=%hex::encode(&id[..8]), amount=v.amount, "Vess accepted");
        true
    } else {
        tracing::warn!("Vess rejected");
        false
    }
}

pub fn handle_pulse(state: &Arc<Mutex<NodeState>>, msg: PulseMessage) {
    if let PulseMessage::VessSubmit(v) = msg { handle_vess_submit(state, &v); }
}