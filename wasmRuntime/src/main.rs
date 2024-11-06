use core::str;
use std::env;
use wasmtime::*;

use anyhow::{Result, Error};
use labeled::{buckle::{Buckle, Component}, Label};


struct RuntimeState {
    current_label: Buckle,
    current_privilege: Component
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
        current_privilege: Component::dc_true()
    };

    let mut store = Store::new(
        &engine, 
        init_state
    );

    linker.func_wrap("runtime", "buckleParse", |mut caller: Caller<'_, RuntimeState>, offset: i32, len: i32| -> Result<Rooted<ExternRef>> {
        let mem = caller.get_export("memory").unwrap().into_memory().unwrap();

        let mut buf = vec![0u8; len as usize];
        mem.read(&caller, offset as usize, &mut buf).unwrap();

        let input_str = str::from_utf8(&buf).unwrap();
        let parsed_buckle = Buckle::parse(input_str);
        
        if parsed_buckle.is_ok() {
            ExternRef::new(&mut caller, parsed_buckle.unwrap())
        } else {
            ExternRef::new(&mut caller, None::<Buckle>)
        }
    })?;

    linker.func_wrap("runtime", "getCurrentLabel", |mut caller: Caller<'_, RuntimeState>| -> Result<Rooted<ExternRef>> {
        let cur_label = caller.data().current_label.clone();
        ExternRef::new(&mut caller, cur_label)
    })?;

    linker.func_wrap("runtime", "printExternRef", |caller: Caller<'_, RuntimeState>, l: Option<Rooted<ExternRef>>| {
        let label = l
            .unwrap()
            .data(&caller).unwrap()
            .downcast_ref::<Buckle>()
            .ok_or_else(|| Error::msg("printExternRef: input externref not a Buckle")).unwrap()
        .clone();

        println!("Entered printExternRef:");
        println!("Input label is: {:#?}\n", label);
    })?;

    linker.func_wrap("runtime", "taintWithLabel", |mut caller: Caller<'_, RuntimeState>, 
     input_ref: Option<Rooted<ExternRef>>| -> Result<Rooted<ExternRef>> {
        println!("Entered taintWithLabel function:");
        let input_label = input_ref.unwrap()
            .data(&caller).unwrap()
            .downcast_ref::<Buckle>()
            .ok_or_else(|| Error::msg("taintWithLabel: input externref not a Buckle")).unwrap()
        .clone();
        println!("Input label is: {:#?}", input_label);
        
        // taint current label with input label
        caller.data_mut().current_label = caller.data().current_label.clone().lub(input_label);
        println!("After tainting, cur_label is: {:#?}\n", caller.data().current_label);
        
        let cur_label = caller.data().current_label.clone();
        ExternRef::new(&mut caller, cur_label)
    })?;

    linker.func_wrap("runtime", "declassify", |mut caller: Caller<'_, RuntimeState>, 
        input_ref: Option<Rooted<ExternRef>>| -> Result<Rooted<ExternRef>> {
        
        let target_secrecy = input_ref.unwrap()
            .data(&caller).unwrap()
            .downcast_ref::<Component>()
            .ok_or_else(|| Error::msg("declassify: input externRef not a Component")).unwrap()
        .clone();

        if (caller.data().current_privilege.clone() & target_secrecy.clone()).implies(&caller.data().current_label.secrecy) {
            let new_label = Buckle::new(target_secrecy.clone(), caller.data().current_label.integrity.clone());
            caller.data_mut().current_label = new_label.clone();
            ExternRef::new(&mut caller, new_label)
        } else {
            let cur_label = caller.data().current_label.clone();
            ExternRef::new(&mut caller, cur_label)
        }
    })?;

    // instantiate module
    let instance = linker.instantiate(&mut store, &module)?;

    // run module
    let run_func = instance.get_typed_func::<(), ()>(&mut store, "run")?;
    run_func.call(&mut store, ())?;

    Ok(())
}

