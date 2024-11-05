use core::str;
use std::env;
use serde_json;
use wasmtime::*;

use anyhow::{Result, Error};
use labeled::{buckle::{Buckle, Component}, Label};


struct RuntimeState {
    current_label: Buckle,
    privilege: Component
}

fn main() -> Result<()>{
    let mut args: Vec<String> = env::args().collect();
    
    if args.len() != 2 {
        return Err(Error::msg("Usage: cargo run -- pathToWasmOrWat"));
    }

    let file_path = args.pop().unwrap();

    // set up and instantiate module
    let engine = Engine::default();
    let module = Module::from_file(&engine, file_path)?;
    let mut linker = Linker::new(&engine);

    // set up init runtime state and create data store for state
    let init_state = RuntimeState{
        current_label: Buckle::public(),
        privilege: Component::dc_true()
    };

    let mut store = Store::new(
        &engine, 
        init_state
    );

    linker.func_wrap("runtime", "getCurrentLabel", |mut caller: Caller<'_, RuntimeState>| -> Result<Rooted<ExternRef>> {
        let cur_label = caller.data().current_label.clone();
        ExternRef::new(&mut caller, cur_label)
       
        // println!("Entered getCurrentLabel function:");
        // let mem = caller.get_export("memory").unwrap().into_memory().unwrap();

        // // generate serialized json string for current label
        // let label = serde_json::to_string(&caller.data().current_label).unwrap();
        // println!("The current label is: {:#?}", caller.data().current_label);

        // // write to memory
        // mem.write(&mut caller, offset as usize, label.as_bytes()).unwrap();

        // let mut buf = vec![0u8; label.len()];
        // mem.read(&caller, offset as usize, &mut buf).unwrap();
        // let ser_label = str::from_utf8(&buf).unwrap();
        // println!("Read serialized label from WebAssembly memory: {}", ser_label);
        // let des_label: Buckle = serde_json::from_str(ser_label).unwrap();
        // println!("Deserialized label from WebAssembly memory: {:#?}\n", des_label);

    })?;

    linker.func_wrap("runtime", "printExternRef", |caller: Caller<'_, RuntimeState>, l: Option<Rooted<ExternRef>>| {
        let label = l
            .unwrap()
            .data(&caller).unwrap()
            .downcast_ref::<Buckle>()
            .ok_or_else(|| Error::msg("externref was not a Buckle")).unwrap()
            .clone();

        println!("Buckle passed to host: {:#?}", label);
    })?;

    linker.func_wrap("runtime", "getCurrentLabelSize", |caller: Caller<'_, RuntimeState>| -> i32 {
        let label = serde_json::to_string(&caller.data().current_label).unwrap();

        label.as_bytes().len() as i32
    })?;

    linker.func_wrap("runtime", "taintWithLabelSize", |mut caller: Caller<'_, RuntimeState>, offset: i32, len: i32| -> i32 {
        let mem = caller.get_export("memory").unwrap().into_memory().unwrap();

        let mut buf = vec![0u8; len as usize];
        mem.read(&caller, offset as usize, &mut buf).unwrap();
        let input_label_str = str::from_utf8(&buf).unwrap();

        let input_label: Buckle = serde_json::from_str(input_label_str).unwrap();
        let result_label = caller.data().current_label.clone().lub(input_label);

        serde_json::to_string(&result_label).unwrap().as_bytes().len() as i32
    })?;

    linker.func_wrap("runtime", "taintWithLabel", |mut caller: Caller<'_, RuntimeState>, 
    src_offset: i32, src_len: i32, dest_offset: i32| {

        println!("Entered taintWithLabel function:");
        println!("Current label is: {:#?}", caller.data().current_label);

        let mem = caller.get_export("memory").unwrap().into_memory().unwrap();

        // read input label from WebAssembly mem and deserialize it
        let mut buf = vec![0u8; src_len as usize];
        mem.read(&caller, src_offset as usize, &mut buf).unwrap();
        let input_label_str = str::from_utf8(&buf).unwrap();

        let input_label: Buckle = serde_json::from_str(input_label_str).unwrap();
        println!("Input label is: {:#?}", input_label);
        
        // taint current label with input label
        caller.data_mut().current_label = caller.data().current_label.clone().lub(input_label);
        println!("After tainting, new current label is: {:#?}\n", caller.data().current_label);

        // write tainted current label to dest_offset, returning it
        let cur_label_ser = serde_json::to_string(&caller.data().current_label).unwrap();
        mem.write(&mut caller, dest_offset as usize, cur_label_ser.as_bytes()).unwrap();
    })?;

    // instantiate module
    let instance = linker.instantiate(&mut store, &module)?;

    // run module
    let run_func = instance.get_typed_func::<(), ()>(&mut store, "run")?;
    run_func.call(&mut store, ())?;

    Ok(())
}

