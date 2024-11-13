mod fs;
mod blobstore;
mod configs;
mod faasten_interface_types;

use core::str;
use std::env;
use std::collections::HashMap;
use extism::*;
use extism_convert::Json;
use fs::{lmdb, BackingStore, FS};
use faasten_interface_types::{DentKind, DentOpen, dent_open, DentOpenResult, DentResult};

use anyhow::{Result, Error};
use labeled::{buckle::{Buckle, Component}, Label};


struct RuntimeState {
    current_label: Buckle,
    current_privilege: Component,
    fs: FS<Box<dyn BackingStore>>,
    dents: HashMap<u64, fs::DirEntry>,
    max_dent_id: u64
}

const BACKING_STORE_PATH : &str = "./backing.fstn";


host_fn!(
    get_current_label(user_data: RuntimeState;) -> Json<Buckle> {
        let state = user_data.get()?;
        let state = state.lock().unwrap();
        
        Ok(Json(state.current_label.clone()))
    }
);

host_fn!(
    buckle_parse(user_data: RuntimeState; input_str: &str) -> Json<Option<Buckle>> {
        let label = Buckle::parse(input_str).ok();
        Ok(Json(label))
    }
);

host_fn!(
    taint_with_label(user_data: RuntimeState; input_label_json: Json<Buckle>) -> Json<Buckle> {
        let state = user_data.get()?;
        let mut state = state.lock().unwrap();
        
        let Json(input_label) = input_label_json;
        let new_label = state.current_label.clone().lub(input_label);
        
        state.current_label = new_label.clone();
        Ok(Json(new_label.clone()))
    }
);

host_fn!(
    declassify(user_data: RuntimeState; target_secrecy_json: Json<Component>) -> Json<Buckle> {
        let state = user_data.get()?;
        let mut state = state.lock().unwrap();

        let Json(target_secrecy) = target_secrecy_json;

        if (target_secrecy.clone() & state.current_privilege.clone()).implies(&state.current_label.secrecy) {
            let new_label = Buckle::new(target_secrecy.clone(), state.current_label.integrity.clone());
            state.current_label = new_label.clone();
        } 
        
        Ok(Json(state.current_label.clone()))
    }
);

host_fn!(
    dent_open(user_data: RuntimeState; dent_open_json: Json<DentOpen>) -> Json<DentOpenResult> {
        let state = user_data.get()?;
        let mut state = state.lock().unwrap();

        let Json(DentOpen{fd: dir_fd, entry}) = dent_open_json;

        let result: Option<(u64, DentKind)> = state.dents
            .get(&dir_fd)
            .cloned()
            .and_then(|base| match (base, entry.unwrap()) {
                ( // Case #1: base = a Directory object. entry = a Name enum. Looking to open an object by it's name 
                    fs::DirEntry::Directory(base_dir),
                    dent_open::Entry::Name(name)
                ) => {
                    base_dir.list(&state.fs).get(&name).map(|dent| {
                        let res_id = state.max_dent_id;
                        let _ = state.dents.insert(res_id, dent.clone());
                        state.max_dent_id += 1;
                        (res_id, dent.into())
                    })
                }
                _ => None
            });
        
        // return a DentOpenResult indicating success or failure
        if let Some(result) = result {
            Ok(Json(DentOpenResult{
                    success: true,
                    fd: result.0,
                    kind: result.1.into()
            }))
        } else {
            Ok(Json(DentOpenResult{
                success: false,
                fd: 0,
                kind: DentKind::DentDirectory.into()
            }))
        }
    }
);

host_fn!(
    dent_close(user_data: RuntimeState; input_fd: u64) -> Json<DentResult> {
        let state = user_data.get()?;
        let mut state = state.lock().unwrap();

        Ok(Json(DentResult{
            success: state.dents.remove(&input_fd).is_some(),
            fd: None,
            data: None
        }))
    }
);

fn main() -> Result<()> {
    let mut args: Vec<String> = env::args().collect();
    if args.len() != 2 {
        return Err(Error::msg("Usage: cargo run -- pathToWasmOrWat"));
    }
    let file_path = args.pop().unwrap();

    // set up FS object
    let dbenv = std::boxed::Box::leak(Box::new(lmdb::get_dbenv(BACKING_STORE_PATH)));
    let fs: FS<Box<dyn BackingStore>> = fs::FS::new(Box::new(&*dbenv));

    // init root direntry
    let mut dents: HashMap<u64, fs::DirEntry> = Default::default();
    dents.insert(0, fs::DirEntry::Directory(fs::ROOT_REF)); 

    let runtime_state = UserData::new(RuntimeState{
        current_label: Buckle::public(),
        current_privilege: Component::dc_true(),
        fs,
        dents,
        max_dent_id: 1
    });

    let wasm_obj = Wasm::file(file_path);
    let manifest = Manifest::new([wasm_obj]);

    let mut plugin = PluginBuilder::new(manifest)
        .with_function("get_current_label", [], [PTR], runtime_state.clone(), get_current_label)
        .with_function("buckle_parse", [PTR], [PTR], runtime_state.clone(), buckle_parse)
        .with_function("taint_with_label", [PTR], [PTR], runtime_state.clone(), taint_with_label)
        .with_function("declassify", [PTR], [PTR], runtime_state.clone(), declassify)
        .with_function("dent_open", [PTR], [PTR], runtime_state.clone(), dent_open)
        .build()
    .unwrap();

    let res = plugin.call::<(), &str>("run", ()).unwrap();
    println!("Return: {}", res);

    Ok(())
}

