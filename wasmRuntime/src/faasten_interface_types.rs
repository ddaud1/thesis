use super::fs::DirEntry;

use serde::{Deserialize, Serialize};

#[derive(serde::Deserialize, serde::Serialize)]
pub struct DentOpen {
    pub fd: u64,
    pub entry: Option<dent_open::Entry>
}


pub mod dent_open {
    #[derive(serde::Deserialize, serde::Serialize)]
        pub enum Entry {
        Name(String),
        Facet(crate::Buckle)
    }
}

#[repr(i32)]
pub enum DentKind {
    DentDirectory = 0,
    DentFile = 1,
    DentFacetedDirectory = 2,
    DentGate = 3,
    DentService = 4,
    DentBlob = 5
}

impl From<&DirEntry> for DentKind {
    fn from(item: &DirEntry) -> Self {
        match item {
            DirEntry::Directory(_) => {DentKind::DentDirectory},
            DirEntry::File(_) => {DentKind::DentFile},
            DirEntry::Gate(_) => {DentKind::DentGate},
            DirEntry::Blob(_) => {DentKind::DentBlob},
            DirEntry::FacetedDirectory(_) => {DentKind::DentFacetedDirectory},
            DirEntry::Service(_) => {DentKind::DentService}
        }
    }
}

impl Into<i32> for DentKind {
    fn into(self) -> i32 {
        match self {
            DentKind::DentDirectory => {0}
            DentKind::DentFile => {1}
            DentKind::DentFacetedDirectory => {2}
            DentKind::DentGate => {3}
            DentKind::DentService => {4}
            DentKind::DentBlob => {5}
        }
    }
}

#[derive(Serialize, Deserialize)]
pub struct DentOpenResult {
    pub success: bool,
    pub fd: u64,
    pub kind: i32
}

#[derive(Serialize, Deserialize)]
pub struct DentResult {
    pub success: bool,
    pub fd: Option<u64>,
    pub data: Option<Vec<u8>>
}