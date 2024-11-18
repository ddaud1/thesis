# Faasten WebAssembly Runtime
This repository contains a WebAssembly runtime which exposes the Faasten Cloudcalls to a Wasm module.  

## Execution Flow
The runtime takes a Wasm module (a .wasm file) as input and calls a "run" function that is provided by the module.  
The Wasm module imports the Cloudcall functions which are provided from the runtime. The "run" function calls  
the imported CloudCalls.

## How to Run
1. In the function directory, compile the function crate to a .wasm with the following command: ```cargo build --target wasm32-unknown-unknown ```
2. In the wasmRuntime directory, execute the following command: ```cargo run -- ../function/target/wasm32-unknown-unknown/debug/function.wasm```
   
