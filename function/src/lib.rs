use externref::{externref, Resource};


struct Label(());

#[externref]
#[link(wasm_import_module = "runtime")]
extern "C" {
    fn getCurrentLabel() -> Resource<Label>;
}


#[externref]
#[export_name = "run"]
pub extern "C" fn run() {

    unsafe {
        let label = getCurrentLabel();
    }

}

