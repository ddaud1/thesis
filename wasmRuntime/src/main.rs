use core::str;
use std::env;
use std::collections::HashMap;
use extism::*;
use extism_convert::Json;
use faasten_interface_types::{dent_create, dent_open, DentKind, dent_update, DentCreate, 
    DentOpen, DentOpenResult, DentResult, DentUpdate, Gate, Service};
use faasten_core::fs::{self, lmdb, BackingStore, DirEntry, CURRENT_LABEL, FS, ROOT_REF};

use anyhow::{Result, Error};
use labeled::{buckle::{Buckle, Component}, Label};


struct RuntimeState {
    fs: FS<Box<dyn BackingStore>>,
    dents: HashMap<u64, DirEntry>,
    max_dent_id: u64
}

const BACKING_STORE_PATH : &str = "./backing.fstn";


host_fn!(
    get_current_label(user_data: RuntimeState;) -> Json<Buckle> {
        Ok(Json(CURRENT_LABEL
            .with(|cl| Buckle::from(cl.borrow().clone()))
        ))
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
        let Json(input_label) = input_label_json;
        Ok(Json(CURRENT_LABEL
            .with(|cl| {
                let new_label = cl.borrow().clone().lub(input_label);
                *cl.borrow_mut() = new_label;//cl.clone().borrow().lub(input_label);
                Buckle::from(cl.borrow().clone())
            })
        ))
    }
);

host_fn!(
    declassify(user_data: RuntimeState; target_secrecy_json: Json<Component>) -> Json<Buckle> {
        let Json(target_secrecy) = target_secrecy_json;

        let res = fs::utils::declassify(target_secrecy);
        match res {
            Ok(l) | Err(l) => Ok(Json(l))
        }
    }
);

// DON'T UNDERSTAND
host_fn!(
    root(user_data: RuntimeState;) -> Json<DentResult> {
        Ok(Json(DentResult{
            success: true,
            fd: None,
            data: None
        }))
    }
);

//used in dent open
struct DentKindWrap {
    kind: DentKind
}

impl From<&DirEntry> for DentKindWrap {
    fn from(item: &DirEntry) -> Self {
        match item {
            DirEntry::Directory(_) => DentKindWrap { kind:DentKind::DentDirectory },
            DirEntry::File(_) => DentKindWrap { kind: DentKind::DentFile },
            DirEntry::Gate(_) => DentKindWrap { kind: DentKind::DentGate },
            DirEntry::Blob(_) => DentKindWrap{ kind: DentKind::DentBlob },
            DirEntry::FacetedDirectory(_) => DentKindWrap { kind: DentKind::DentFacetedDirectory },
            DirEntry::Service(_) => DentKindWrap { kind: DentKind::DentService }
        }
    }
}

// INCOMPLETE
host_fn!(
    dent_open(user_data: RuntimeState; dent_open_json: Json<DentOpen>) -> Json<DentOpenResult> {
        let state = user_data.get()?;
        let mut state = state.lock().unwrap();

        let Json(DentOpen{fd: dir_fd, entry}) = dent_open_json;

        let result: Option<(u64, DentKindWrap)> = state.dents
            .get(&dir_fd)
            .cloned()
            .and_then(|base| match (base, entry.unwrap()) {
                ( // Case #1: base = a Directory object. entry = a Name enum. Looking to open an object by it's name 
                    DirEntry::Directory(base_dir),
                    dent_open::Entry::Name(name)
                ) => {
                    base_dir.list(&state.fs).get(&name).map(|dent| {
                        let res_id = state.max_dent_id;
                        let _ = state.dents.insert(res_id, dent.clone());
                        state.max_dent_id += 1;
                        (res_id, dent.into())
                    })
                }
                _ => todo!()
            });
        
        // return a DentOpenResult indicating success or failure
        if let Some(result) = result {
            Ok(Json(DentOpenResult{
                    success: true,
                    fd: result.0,
                    kind: result.1.kind.into()
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

// INCOMPLETE
host_fn!(
    dent_create(user_data: RuntimeState; dent_create_json: Json<DentCreate>) -> Json<DentResult> {
        let state = user_data.get()?;
        let mut state = state.lock().unwrap();
        
        let Json(DentCreate{label, kind}) = dent_create_json;

        // if kind is none, return failure
        if kind.is_none() {
            return Ok(Json(DentResult{success: false, fd: None, data: None}));
        }

        // get the actual label and kind passed into dent create. label defaults to public
        let kind = kind.unwrap();
        let label = label.unwrap_or(Buckle::public());

        let entry: DirEntry = match kind {
            dent_create::Kind::Directory => state.fs.create_directory(label),
            dent_create::Kind::File => state.fs.create_file(label),
            dent_create::Kind::FacetedDirectory => state.fs.create_faceted_directory(),
            _ => todo!()
        };

        let res_id = state.max_dent_id;
        let _ = state.dents.insert(res_id, entry);
        state.max_dent_id += 1;

        Ok(Json(DentResult{
            success: true,
            fd: Some(res_id),
            data: None
        }))
    }
);

// INCOMPLETE
host_fn!(
    dent_update(user_data: RuntimeState; dent_update_json: Json<DentUpdate>) -> Json<DentResult> {
        let state = user_data.get()?;
        let state = state.lock().unwrap();

        let Json(DentUpdate{fd, kind}) = dent_update_json;

        // if kind is none, return failure
        if kind.is_none() {
            return Ok(Json(DentResult{success: false, fd: None, data: None}))
        }

        let kind = kind.unwrap();

        match kind {
            dent_update::Kind::File(data) => {
                if let Some(DirEntry::File(file)) = state.dents.get(&fd) {
                    file.write(data, &state.fs).unwrap();
                } else {
                    return Ok(Json(DentResult{success: false, fd: None, data: None}));
                }
            }
            dent_update::Kind::Gate(Gate{..}) => todo!(),
            dent_update::Kind::Service(Service{..}) => todo!(),
            dent_update::Kind::Blob(_) => todo!()
        };

        Ok(Json(DentResult{
            success: true,
            fd: None,
            data: None
        }))
    }
);

host_fn!(
    dent_read(user_data: RuntimeState; fd: u64) -> Json<DentResult> {
        let state = user_data.get()?;
        let state = state.lock().unwrap();

        let result = state.dents.get(&fd).and_then(|entry| {
            match entry {
                DirEntry::File(file) => Some(file.read(&state.fs)),
                _ => None
            }
        });

        Ok(Json(DentResult{
            success: result.is_some(),
            fd: Some(fd),
            data: result
        }))
    }
);

fn main() -> Result<()> {
    let mut args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        return Err(Error::msg("Usage: cargo run -- pathToWasm"));
    }
    let file_path = args.pop().unwrap();

    // set up FS object, label, and privilege
    let dbenv = std::boxed::Box::leak(Box::new(lmdb::get_dbenv(BACKING_STORE_PATH)));
    let fs: FS<Box<dyn BackingStore>> = FS::new(Box::new(&*dbenv));
    
    // set up label and privilege
    faasten_core::fs::utils::clear_label();
    faasten_core::fs::utils::set_my_privilge(Component::dc_true());

    // init root direntry
    let mut dents: HashMap<u64, DirEntry> = Default::default();
    dents.insert(0, DirEntry::Directory(ROOT_REF)); 

    let runtime_state = UserData::new(RuntimeState{
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
        .with_function("root", [], [PTR], runtime_state.clone(), root)
        .with_function("dent_open", [PTR], [PTR], runtime_state.clone(), dent_open)
        .with_function("dent_close", [ValType::I64], [PTR], runtime_state.clone(), dent_close)
        .with_function("dent_create", [PTR], [PTR], runtime_state.clone(), dent_create)
        .with_function("dent_update", [PTR], [PTR], runtime_state.clone(), dent_update)
        .with_function("dent_read", [ValType::I64], [PTR], runtime_state.clone(), dent_read)
        .build()
    .unwrap();

    let res = plugin.call::<(), &str>("run", ()).unwrap();
    println!("Return: {}", res);

    Ok(())
}

