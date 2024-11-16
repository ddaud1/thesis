use extism_pdk::*;
use labeled::buckle::{Buckle, Component};
use faasten_core::faasten_interface_types::{DentOpen, DentOpenResult, DentCreate, dent_create, DentResult};

#[host_fn]
extern "ExtismHost" {
    fn get_current_label() -> Json<Buckle>;
    fn buckle_parse(input_str: &str) -> Json<Option<Buckle>>;
    fn taint_with_label(input_label: Json<Buckle>) -> Json<Buckle>;
    fn declassify(target_secrecy: Json<Component>) -> Json<Buckle>;
    fn dent_open(dent_open_json: Json<DentOpen>) -> Json<DentOpenResult>;
    fn dent_create(dent_create_json: Json<DentCreate>) -> Json<DentResult>;
}


#[plugin_fn]
pub fn run() -> FnResult<String> {
    unsafe {
        let Json(label1) = get_current_label().unwrap();
        let Json(label2) = buckle_parse("Dwaha,Dwaha").unwrap();
        let Json(label3) = taint_with_label(Json(label2.clone().unwrap())).unwrap();
        let Json(label4) = get_current_label().unwrap();
        let Json(label5) = declassify(Json(Component::dc_true())).unwrap();

        let Json(de_result) = dent_create(Json(DentCreate{label: label2.unwrap(), kind: Some(dent_create::Kind::File)})).unwrap();
        
        Ok(format!("1:{:#?}\n2:{:#?}\n3:{:#?}\n4:{:#?}\n5:{:#?}", 
            label1, 
            label2.unwrap(), 
            label3, label4, label5))
    }
}

