use core::str;
use std::env;
use std::collections::HashMap;
use std::io::Write;
use extism::*;
use extism_convert::Json;
use faasten_interface_types::{dent_create, dent_open, dent_update, gate,
    DentCreate, DentKind, DentLink, DentListResult, DentLsFaceted, DentLsFacetedResult, DentLsGateResult,
    DentOpen, DentOpenResult, DentResult, DentUnlink, DentUpdate, Service,
    DentInvoke, DentInvokeResult, BlobWrite, BlobResult, BlobFinalize, BlobRead, BlobClose};
use faasten_core::fs::{self, lmdb, BackingStore, DirEntry, DirectGate, Gate, 
    HttpVerb, RedirectGate, CURRENT_LABEL, FS, ROOT_REF};
use faasten_core::blobstore::{Blob, Blobstore, NewBlob};
use labeled::{buckle::{Buckle, Component}, Label};


struct RuntimeState {
    fs: FS<Box<dyn BackingStore>>,
    blobstore: Blobstore,
    dents: HashMap<u64, DirEntry>,
    max_dent_id: u64,
    blobs: HashMap<u64, Blob>,
    max_blob_id: u64,
    create_blobs: HashMap<u64, NewBlob>
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

host_fn!(
    root(user_data: RuntimeState;) -> Json<DentResult> {
        Ok(Json(DentResult{
            success: true,
            fd: Some(0),
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
                (
                    // Case #2: base = a FacetedDirectory object. entry = a Facet enum. Looking to open an object by it's label
                    DirEntry::FacetedDirectory(base_dir),
                    dent_open::Entry::Facet(label)
                ) => {
                    let dent = DirEntry::Directory(base_dir.open(&label.into(), &state.fs));
                    let res_id = state.max_dent_id;
                    let _ = state.dents.insert(res_id, dent.clone());
                    state.max_dent_id += 1;
                    Some((res_id, (&dent).into()))
                }
                (
                    // Case #3: base = a FacetedDirectory object. entry = a Name enum. Name contains a string which represent a label
                    DirEntry::FacetedDirectory(base_dir),
                    dent_open::Entry::Name(label_name)
                ) => {
                    if let Ok(label) = Buckle::parse(label_name.as_str()) {
                        let dent = DirEntry::Directory(base_dir.open(&label, &state.fs));
                        let res_id = state.max_dent_id;
                        let _ = state.dents.insert(res_id, dent.clone());
                        state.max_dent_id += 1;
                        Some((res_id, (&dent).into()))
                    } else {
                        None
                    }
                }
                _ => None
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


        let maybe_entry: Option<DirEntry> = match kind {
            dent_create::Kind::Directory => Some(state.fs.create_directory(label)),
            dent_create::Kind::File => Some(state.fs.create_file(label)),
            dent_create::Kind::FacetedDirectory => Some(state.fs.create_faceted_directory()),
            dent_create::Kind::Blob(blobfd) => {
                // get blob from blobs table. create a blob entry in dents table which wraps around the blob name
                let blob = state.blobs.get(&blobfd);
                
                if blob.is_some() { state.fs.create_blob(label, blob.unwrap().name.clone()).ok() }
                else {None}
            }
            dent_create::Kind::Gate(faasten_interface_types::Gate {kind: gate_kind}) => {
                if gate_kind.is_none() {
                    None
                } 
                else {
                    let gate_kind = gate_kind.unwrap();
                    match gate_kind {
                        // Case #1: creating a direct gate
                        gate::Kind::Direct(dg) => {
                            let Some(function) = dg.function
                            else {
                                log::info!("No function provided when creating gate");
                                return Ok(Json(DentResult{success: false, fd: None, data: None}));
                            };
                            
                            // get the function's app image
                            let Some(DirEntry::Blob(app_image)) = state.dents.get(&function.app_image)
                            else {
                                log::info!("Failed to read function's app image when creating gate");
                                return Ok(Json(DentResult{success: false, fd: None, data: None}));
                            };

                            // get the function's runtime image
                            let Some(DirEntry::Blob(runtime_image)) = state.dents.get(&function.runtime_image)
                            else {
                                log::info!("Failed to read function's runtime image when creating gate");
                                return Ok(Json(DentResult{success: false, fd: None, data: None}));
                            };

                            // create an internal version of the function
                            let new_func = fs::Function {
                                memory: function.memory as usize,
                                app_image: app_image.get(&state.fs).unwrap().unlabel().clone(),
                                runtime_image: runtime_image.get(&state.fs).unwrap().unlabel().clone(),
                                kernel: "Kernel Not Used".to_string()
                            };

                            // create the direct gate
                            state.fs.create_direct_gate(label, 
                                DirectGate {
                                    privilege: dg.privilege.unwrap().into(),
                                    invoker_integrity_clearance: dg.invoker_integrity_clearance.unwrap().into(),
                                    declassify: dg.declassify.map(|d| d.into()).unwrap_or(Component::dc_true()),
                                    function: new_func
                                }
                            ).ok()
                        }
                        // Case #2: creating a redirect gate
                        gate::Kind::Redirect(rdg) => {
                            let maybe_inner_gate = state.dents.get(&rdg.gate);
                            
                            if let Some(DirEntry::Gate(gate_objref)) = maybe_inner_gate {
                                state.fs.create_redirect_gate(label, 
                                    RedirectGate {
                                        privilege: rdg.privilege.unwrap().into(),
                                        invoker_integrity_clearance: rdg.invoker_integrity_clearance.unwrap().into(),
                                        declassify: rdg.declassify.map(|d| d.into()).unwrap_or(Component::dc_true()),
                                        gate: *gate_objref
                                    }
                                ).ok()
                            } else {
                                log::info!("Failed to get inner gate when creating redirect gate");
                                return Ok(Json(DentResult{success: false, fd: None, data: None}));
                            }
                        }
                    }
                }
            },
            dent_create::Kind::Service(Service {
                taint,
                privilege,
                invoker_integrity_clearance,
                url,
                verb,
                mut headers
            }) => {
                let verb = HttpVerb::from_i32(verb).unwrap_or(HttpVerb::HEAD);
                let headers: std::collections::BTreeMap<String, String> = headers.drain().collect();
                
                state.fs.create_service(label, 
                    fs::Service {
                        taint: taint.unwrap().into(),
                        privilege: privilege.unwrap().into(),
                        invoker_integrity_clearance: invoker_integrity_clearance.unwrap().into(),
                        url,
                        verb,
                        headers
                    }
                ).ok()
            }
        };

        // if entry is valid, insert into dents table
        if let Some(entry) = maybe_entry {
            let res_id = state.max_dent_id;
            let _ = state.dents.insert(res_id, entry);
            state.max_dent_id += 1;

            Ok(Json(DentResult{
                success: true,
                fd: Some(res_id),
                data: None
            }))
        } else {
            Ok(Json(DentResult{
                success: false,
                fd: None,
                data: None
            }))
        }
    }
);

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

        let result = match kind {
            dent_update::Kind::File(data) => {
                if let Some(DirEntry::File(file_objref)) = state.dents.get(&fd) {
                    file_objref.write(data, &state.fs).ok()
                } else { None }
            }
            dent_update::Kind::Blob(blobfd) => {
                let new_blob = state.blobs.get(&blobfd);
                if new_blob.is_none() {
                    log::info!("Failed to update object with fd {}", fd);
                    return Ok(Json(DentResult{success: false, fd: None, data: None}));
                }
                let new_blob = new_blob.unwrap();

                if let Some(DirEntry::Blob(blob_objref)) = state.dents.get(&fd) {
                    blob_objref.replace(new_blob.name.clone(), &state.fs).ok()
                } else { None }
            }
            dent_update::Kind::Gate(faasten_interface_types::Gate { kind }) => {
                if let Some(DirEntry::Gate(gate_objref)) = state.dents.get(&fd) {
                    if let Some( kind ) = kind {
                        match kind {
                            // Case #1: replacing a direct gate
                            gate::Kind::Direct(dg_intf) => {
                                // will use this to replace the old gate in the backing store
                                let mut new_gate;
                                
                                // get the old gate from the backing store
                                if let Some(Gate::Direct(dg_core)) = gate_objref.get(&state.fs).map(|g| g.unlabel().clone()) {
                                    new_gate = dg_core;
                                } else {
                                    log::info!("Failed to update object with fd {}", fd);
                                    return Ok(Json(DentResult{success: false, fd: None, data: None}));
                                }

                                // replace gate's function field, if user provided one
                                if let Some(function) = dg_intf.function {
                                    // replace function's fields if user provided a valid fd for them

                                    // replacing app image
                                    if function.app_image > 0 {
                                        let Some(DirEntry::Blob(app_image)) = state.dents.get(&function.app_image) 
                                        else {
                                            log::info!("Failed to update object with fd {}", fd);
                                            return Ok(Json(DentResult{success: false, fd: None, data: None}));
                                        };

                                        new_gate.function.app_image = app_image.get(&state.fs).unwrap().unlabel().clone();
                                    }

                                    // replacing runtime image
                                    if function.runtime_image > 0 {
                                        let Some(DirEntry::Blob(runtime_image)) = state.dents.get(&function.runtime_image)
                                        else {
                                            log::info!("Failed to update object with fd {}", fd);
                                            return Ok(Json(DentResult{success: false, fd: None, data: None}));
                                        };

                                        new_gate.function.runtime_image = runtime_image.get(&state.fs).unwrap().unlabel().clone();
                                    }

                                    // kernel not used, so not replaced
                                    
                                    // replacing memory
                                    if function.memory > 0 {
                                        new_gate.function.memory = function.memory as usize;
                                    }
                                }

                                // replace gate's privilege, if user provided one
                                if let Some(privilege) = dg_intf.privilege {
                                    new_gate.privilege = privilege.into();
                                }

                                // replace gate's invoker integrity clearance, if user provided one
                                if let Some(invoker_integrity_clearance) = dg_intf.invoker_integrity_clearance {
                                    new_gate.invoker_integrity_clearance = invoker_integrity_clearance.into();
                                }

                                gate_objref.replace(Gate::Direct(new_gate), &state.fs).ok()
                            }
                            // Case #2 replacing an indirect gate
                            gate::Kind::Redirect(rdg_intf) => {
                                // will use this to replace the old gate in the backing store
                                let mut new_gate;

                                // get the old gate from the backing store
                                if let Some(Gate::Redirect(rdg_core)) = gate_objref.get(&state.fs).map(|g| g.unlabel().clone()) {
                                    new_gate = rdg_core;
                                } else {
                                    log::info!("Failed to update object with fd {}", fd);
                                    return Ok(Json(DentResult{success: false, fd: None, data: None}));
                                }

                                // replace inner gate, if user provided a valid fd for it
                                if rdg_intf.gate > 0 {
                                    if let Some(DirEntry::Gate(inner_gate_objref)) = state.dents.get(&rdg_intf.gate) {
                                        new_gate.gate = *inner_gate_objref;
                                    } else{
                                        log::info!("Failed to update object with fd {}", fd);
                                        return Ok(Json(DentResult{success: false, fd: None, data: None}));
                                    }
                                }

                                // replace gate's privilege, if user provided one
                                if let Some(privilege) = rdg_intf.privilege {
                                    new_gate.privilege = privilege.into();
                                }

                                // replace gate's invoker integrity clearance, if user provided one
                                if let Some(invoker_integrity_clearance) = rdg_intf.invoker_integrity_clearance {
                                    new_gate.invoker_integrity_clearance = invoker_integrity_clearance;
                                }

                                gate_objref.replace(Gate::Redirect(new_gate), &state.fs).ok()
                            }
                        }
                    } else { None }
                } else { None }
            },
            dent_update::Kind::Service( Service{
                taint,
                privilege,
                invoker_integrity_clearance,
                url,
                verb,
                mut headers
            } ) => {
                if let Some(DirEntry::Service(service_objref)) = state.dents.get(&fd) {
                    let verb = HttpVerb::from_i32(verb).unwrap_or(HttpVerb::HEAD).into();
                    let headers: std::collections::BTreeMap<String, String> = headers.drain().collect();
                    
                    service_objref.replace(
                        fs::Service {
                            taint: taint.unwrap().into(),
                            privilege: privilege.unwrap().into(),
                            invoker_integrity_clearance: invoker_integrity_clearance.unwrap().into(),
                            url,
                            verb,
                            headers
                        },
                        &state.fs
                    ).ok()
                } else {
                    None
                }
            }
        };

        if result.is_some() {
            Ok(Json(DentResult{
                success: true,
                fd: None,
                data: None
            }))
        } else {
            log::info!("Failed to update object with fd {}", fd);
            return Ok(Json(DentResult{success: false, fd: None, data: None}));
        }
        
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

host_fn!(
    dent_link(user_data: RuntimeState; dent_link_json: Json<DentLink>) -> Json<DentResult> {
        let state = user_data.get()?;
        let state = state.lock().unwrap();

        let Json(DentLink{dir_fd, name, target_fd}) = dent_link_json;

        let base_dir_m = state.dents.get(&dir_fd).cloned();
        let target_obj_m = state.dents.get(&target_fd).cloned();
        let result = base_dir_m.zip(target_obj_m).and_then(|(base, target)| {
            match base {
                DirEntry::Directory(base_dir) => base_dir
                    .link(name, target, &state.fs)
                    .map_err(|e| Into::into(e)),
                _ => Err(fs::FsError::NotADir)             
            }.ok()
        });

        Ok(Json(DentResult{
            success: result.is_some(),
            fd: None, 
            data: None}))
    }
);

host_fn!(
    dent_unlink(user_data: RuntimeState; dent_unlink_json: Json<DentUnlink>) -> Json<DentResult> {
        let state = user_data.get()?;
        let state = state.lock().unwrap();

        let Json(DentUnlink{dir_fd, name}) = dent_unlink_json;

        let result = state.dents.get(&dir_fd).cloned().and_then(|entry| {
            match entry {
                DirEntry::Directory(base_dir) => base_dir.unlink(&name, &state.fs).ok(),
                _ => None
            }
        });

        Ok(Json(DentResult{
            success: result.unwrap_or(false),
            fd: Some(dir_fd),
            data: None
        }))
    }
);

host_fn!(
    dent_list(user_data: RuntimeState; dir_fd: u64) -> Json<DentListResult> {
        let state = user_data.get()?;
        let state = state.lock().unwrap();

        let result = state.dents.get(&dir_fd).and_then(|entry| {
            match entry {
                DirEntry::Directory(dir_objref) => Some(
                    dir_objref
                        .list(&state.fs)
                        .iter()
                        .map(
                            |(name, direntry)| {
                                let kind = match direntry {
                                    DirEntry::Directory(_) => DentKind::DentDirectory,
                                    DirEntry::File(_) => DentKind::DentFile,
                                    DirEntry::FacetedDirectory(_) => DentKind::DentFacetedDirectory,
                                    DirEntry::Gate(_) => DentKind::DentGate,
                                    DirEntry::Service(_) => DentKind::DentService,
                                    DirEntry::Blob(_) => DentKind::DentBlob
                                };

                                (name.clone(), kind as i32)
                            }
                        )
                        .collect()
                ),
                _ => {
                    log::info!("List failed. Not a directory.");
                    None
                }
            }
        });

        if let Some(entries) = result {
            Ok(Json(DentListResult{success: true, entries}))
        } else {
            Ok(Json(DentListResult{success: false, entries: Default::default()}))
        }
    }
);

host_fn!(
    dent_ls_faceted(user_data: RuntimeState; dent_ls_faceted_json: Json<DentLsFaceted>) -> Json<DentLsFacetedResult> {
        let state = user_data.get()?;
        let state = state.lock().unwrap();

        let Json(DentLsFaceted { fd: fdir_fd, clearance }) = dent_ls_faceted_json;
        
        // clearance defaults to public
        let clearance = clearance.unwrap_or(Buckle::public());

        let result  = state.dents.get(&fdir_fd).and_then(|entry| {
            match entry {
                DirEntry::FacetedDirectory(fdir_objref) => Some(
                    fdir_objref
                        .list(&state.fs, &clearance)
                        .iter()
                        .map(|(label, _)| label.clone().into())
                        .collect()
                ),
                _ => {
                    log::info!("List failed. Not a faceted directory.");
                    None
                }
            }
        });

        if let Some(facets) = result {
            Ok(Json(DentLsFacetedResult {success: true, facets} ))
        } else {
            Ok(Json(DentLsFacetedResult{success: false, facets: Default::default()}))
        }
    }
);

host_fn!(
    dent_ls_gate(user_data: RuntimeState; gate_fd: u64) -> Json<DentLsGateResult> {
        let state = user_data.get()?;
        let mut state = state.lock().unwrap();

        let result = state.dents.get(&gate_fd).map(Clone::clone).and_then(|entry| {
            match entry {
                DirEntry::Gate(gate_objref) => Some(
                    match gate_objref.get(&state.fs).unwrap().unlabel() {
                        // Case #1: List a Direct Gate
                        Gate::Direct(dg_core) => {
                            // open the gate's app image and get its fd
                            let app_image_fd = {
                                let blob_id = state.max_blob_id;
                                state.max_blob_id += 1;
                                
                                let Some(blob) = state
                                    .blobstore
                                    .open(dg_core.function.app_image.clone())
                                    .ok()
                                else {
                                    log::info!("List failed. Failed to open app image.");
                                    return None;
                                };
                                state.blobs.insert(blob_id, blob);
                                
                                blob_id
                            };

                            // open the gate's runtime image and get its fd
                            let runtime_image_fd = {
                                let blob_id = state.max_blob_id;
                                state.max_blob_id += 1;

                                let Some(blob) = state
                                    .blobstore
                                    .open(dg_core.function.runtime_image.clone())
                                    .ok()
                                else {
                                    log::info!("List failed. Failed to open runtime image.");
                                    return None;
                                };
                                state.blobs.insert(blob_id, blob);

                                blob_id
                            };

                            // kernel image not used so don't open
                            
                            // create the interface version of the function
                            let function_intf = faasten_interface_types::Function {
                                memory: dg_core.function.memory as u64,
                                app_image: app_image_fd,
                                runtime_image: runtime_image_fd,
                                kernel: 0 // not used
                            };

                            // return user-side direct gate
                            faasten_interface_types::Gate {
                                kind: Some(gate::Kind::Direct(
                                    faasten_interface_types::DirectGate { 
                                        privilege: Some(dg_core.privilege.clone()), 
                                        invoker_integrity_clearance: Some(dg_core.invoker_integrity_clearance.clone()), 
                                        function: Some(function_intf), 
                                        declassify: Some(dg_core.declassify.clone())
                                    }
                                ))
                            }
                        }
                        // Case #2: List a Redirect Gate
                        Gate::Redirect(rdg_core) => {
                            // return user-side redirect gate
                            faasten_interface_types::Gate {
                                kind: Some(gate::Kind::Redirect(
                                    faasten_interface_types::RedirectGate { 
                                        privilege: Some(rdg_core.privilege.clone()), 
                                        invoker_integrity_clearance: Some(rdg_core.invoker_integrity_clearance.clone()), 
                                        gate: 0, 
                                        declassify: Some(rdg_core.declassify.clone())
                                    }
                                ))
                            }
                        }
                    }
                ),
                _ => {
                    log::info!("List failed. Not a gate.");
                    None
                }
            }
        });

        Ok(Json(DentLsGateResult {success: result.is_some(), gate: result}))
    }
);

host_fn!(
    dent_invoke(user_data: RuntimeState; dent_invoke_json: Json<DentInvoke>) -> Json<DentInvokeResult> {
        let state = user_data.get()?;
        let state = state.lock().unwrap();

        let Json(DentInvoke { .. }) = dent_invoke_json;

        // SKIPPING UNTIL I UNDERSTAND IT BETTER

        Ok(Json(DentInvokeResult{success: false, fd: None, data: vec![], headers: Default::default()}))
    }
);

host_fn!(
    dent_get_blob(user_data: RuntimeState; fd: u64) -> Json<BlobResult> {
        let state = user_data.get()?;
        let mut state = state.lock().unwrap();

        match state.dents.get(&fd) {
            Some(DirEntry::Blob(blob_objref)) => {
                // get the blob from the blobstore using it's name in the fs
                let blob = state
                    .blobstore
                    .open(blob_objref.read(&state.fs))
                .expect("Get blob failed. Couldn't open blob");
                
                // insert the fetched blob in the table of open blobs
                let blobfd = state.max_blob_id;
                state.max_blob_id += 1;
                let len = blob.len().expect("Get blob failed. Couldn't find blob length");
                state.blobs.insert(blobfd, blob);

                Ok(Json( BlobResult {success: true, fd: blobfd, len, data: None} ))
            }
            _ => Ok(Json(BlobResult {success: false, fd: 0, len: 0, data: None}))
        }
    }
);

host_fn!(
    blob_create(user_data: RuntimeState;) -> Json<BlobResult> {
        let state = user_data.get()?;
        let mut state = state.lock().unwrap();

        match state.blobstore.create() {
            Ok(newblob) => {
                let blobfd = state.max_blob_id;
                state.max_blob_id += 1;
                state.create_blobs.insert(blobfd, newblob);

                Ok(Json(BlobResult {success: true, fd: blobfd, len: 0, data: None}))
            },
            Err(e) => Ok(Json(BlobResult{success: false, fd: 0, len: 0, data: Some(e.to_string().into())}))
        }
    }
);

host_fn!(
    blob_write(user_data: RuntimeState; blob_write_json: Json<BlobWrite>) -> Json<BlobResult> {
        let state = user_data.get()?;
        let mut state = state.lock().unwrap();

        let Json(BlobWrite { fd, data }) = blob_write_json;

        if let Some(newblob) = state.create_blobs.get_mut(&fd) {
            match newblob.write(&data) {
                Ok(len) => Ok(Json(BlobResult { success: true, fd, len: len as u64, data: None })),
                Err(e) => Ok(Json(BlobResult { success: false, fd, len: 0, data: Some(e.to_string().into()) }))
            }
        } else {
            Ok(Json(BlobResult {success: false, fd: 0, len: 0, data: None }))
        }
    }
);

host_fn!(
    blob_finalize(user_data: RuntimeState; blob_finalize_json: Json<BlobFinalize>) -> Json<BlobResult> {
        let state = user_data.get()?;
        let mut state = state.lock().unwrap();

        let Json(BlobFinalize { fd }) = blob_finalize_json;

        if let Some(newblob) = state.create_blobs.remove(&fd) {
            let len = newblob.len() as u64;
            
            match state.blobstore.save(newblob) {
                Ok(finalized_blob) => {
                    state.blobs.insert(fd, finalized_blob);
                    Ok(Json(BlobResult { success: true, fd,  len, data: None}))
                }
                Err(e) => Ok(Json(BlobResult { success: false, fd, len, data: Some(e.to_string().into()) }))
            }
        } else {
            Ok(Json(BlobResult { success: false, fd, len: 0, data: None }))
        }
    }
);

host_fn!(
    blob_read(user_data: RuntimeState; blob_read_json: Json<BlobRead>) -> Json<BlobResult> {
        let state = user_data.get()?;
        let state = state.lock().unwrap();

        let Json(BlobRead { fd, offset: maybe_offset, length: maybe_length }) = blob_read_json;

        // offset defaults to 0 and length defaults to 4096 bytes (4KB)
        let offset = maybe_offset.unwrap_or(0);
        let length = maybe_length.unwrap_or(4096);

        if let Some(blob) = state.blobs.get(&fd) {
            let mut buf = vec![0; length as usize];

            match blob.read_at(&mut buf, offset) {
                Ok(num_bytes_read) => {
                    buf.resize(num_bytes_read, 0);
                    Ok(Json(BlobResult { success: true, fd, len: num_bytes_read as u64, data: Some(buf) }))
                },
                Err(e) => Ok(Json(BlobResult { success: false, fd, len: 0, data: Some(e.to_string().into()) }))
            }
        } else {
            Ok(Json(BlobResult { success: false, fd, len: 0, data: None }))
        }
    }
);

host_fn!(
    blob_close(user_data: RuntimeState; blob_close_json: Json<BlobClose>) -> Json<BlobResult> {
        let state = user_data.get()?;
        let mut state = state.lock().unwrap();

        let Json(BlobClose { fd }) = blob_close_json;

        if state.blobs.remove(&fd).is_some() {
            Ok(Json(BlobResult { success: true, fd, len: 0, data: None }))
        } else {
            Ok(Json(BlobResult { success: false, fd, len: 0, data: None }))
        }
    }
);

fn main() -> Result<(), & 'static str> {
    // set RUST_LOG environment variable to configure log level
    let env = env_logger::Env::default()
        .filter_or("RUST_LOG", "warn");
    env_logger::init_from_env(env);

    let mut args: Vec<String> = env::args().collect();
    if args.len() != 2 {
        return Err("Usage: cargo run -- pathToWasm");
    }
    let file_path = args.pop().unwrap();

    // set up FS object, label, and privilege
    let dbenv = std::boxed::Box::leak(Box::new(lmdb::get_dbenv(BACKING_STORE_PATH)));
    let fs: FS<Box<dyn BackingStore>> = FS::new(Box::new(&*dbenv));
    
    /* PRIVILEGE SET TO FALSE FOR TESTING PURPOSES (OVERRIDES LABEL CHECKS). EVENTUALLY SET BACK TO TRUE! */
    // set up label and privilege
    fs::utils::clear_label();
    fs::utils::set_my_privilge(Component::dc_false());

    // init root direntry
    let mut dents: HashMap<u64, DirEntry> = Default::default();
    dents.insert(0, DirEntry::Directory(ROOT_REF));

    // initialize fs
    if !fs.initialize() {
        println!("Existing root detected.");
    }
 
    let runtime_state = UserData::new(RuntimeState{
        fs,
        blobstore: Blobstore::default(),
        dents,
        max_dent_id: 1,
        blobs: Default::default(),
        max_blob_id: 1,
        create_blobs: Default::default()
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
        .with_function("dent_link", [PTR], [PTR], runtime_state.clone(), dent_link)
        .with_function("dent_unlink", [PTR], [PTR], runtime_state.clone(), dent_unlink)
        .with_function("dent_list", [ValType::I64], [PTR], runtime_state.clone(), dent_list)
        .with_function("dent_ls_faceted", [PTR], [PTR], runtime_state.clone(), dent_ls_faceted)
        .with_function("dent_ls_gate", [ValType::I64], [PTR], runtime_state.clone(), dent_ls_gate)
        .with_function("dent_invoke", [PTR], [PTR], runtime_state.clone(), dent_invoke)
        .with_function("dent_get_blob", [ValType::I64], [PTR], runtime_state.clone(), dent_get_blob)
        .with_function("blob_create", [], [PTR], runtime_state.clone(), blob_create)
        .with_function("blob_write", [PTR], [PTR], runtime_state.clone(), blob_write)
        .with_function("blob_finalize", [PTR], [PTR], runtime_state.clone(), blob_finalize)
        .with_function("blob_read", [PTR], [PTR], runtime_state.clone(), blob_read)
        .with_function("blob_close", [PTR], [PTR], runtime_state.clone(), blob_close)
        .build()
    .unwrap();

    let res = plugin.call::<(), &str>("run", ()).unwrap();
    println!("Return: {}", res);

    Ok(())
}

