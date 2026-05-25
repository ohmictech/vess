use anyhow::{Context, Result};
use vess_mesh::{
    decode_mesh_contact, decode_mesh_contact_string, encode_mesh_contact,
    encode_mesh_contact_string, validate_mesh_contact, MeshCarrierContact,
};

use crate::persistence::unhex_key;

pub(crate) fn encode_contact_bytes(contact: &MeshCarrierContact) -> Result<Vec<u8>> {
    validate_mesh_contact(contact).context("validate mesh contact")?;
    encode_mesh_contact(contact).context("serialize compact mesh contact")
}

pub(crate) fn encode_contact_string(contact: &MeshCarrierContact) -> Result<String> {
    validate_mesh_contact(contact).context("validate mesh contact")?;
    encode_mesh_contact_string(contact).context("serialize compact mesh contact string")
}

pub(crate) fn decode_contact_bytes(bytes: &[u8]) -> Result<MeshCarrierContact> {
    let contact = decode_mesh_contact(bytes).context("deserialize mesh contact")?;
    validate_mesh_contact(&contact).context("validate mesh contact")?;
    Ok(contact)
}

pub(crate) fn parse_contact_string(value: &str) -> Result<MeshCarrierContact> {
    let contact = decode_mesh_contact_string(value).context("parse mesh contact string")?;
    validate_mesh_contact(&contact).context("validate mesh contact")?;
    Ok(contact)
}

pub(crate) fn contact_node_id_bytes(contact: &MeshCarrierContact) -> Option<[u8; 32]> {
    validate_mesh_contact(contact).ok()?;
    contact
        .node_id()
        .map(|node_id: vess_mesh::MeshNodeId| *node_id.as_bytes())
}

pub(crate) fn contact_bytes_node_id(bytes: &[u8]) -> Option<[u8; 32]> {
    decode_contact_bytes(bytes)
        .ok()
        .and_then(|contact| contact_node_id_bytes(&contact))
}

pub(crate) fn parse_node_id_hex(value: &str) -> Option<[u8; 32]> {
    unhex_key(value).ok()
}
