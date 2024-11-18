use extism_pdk::*;
use labeled::buckle::{Buckle, Component};
use faasten_interface_types::{DentOpen, DentOpenResult, DentCreate, dent_create, 
    DentResult, DentUpdate, dent_update};

#[host_fn]
extern "ExtismHost" {
    fn get_current_label() -> Json<Buckle>;
    fn buckle_parse(input_str: &str) -> Json<Option<Buckle>>;
    fn taint_with_label(input_label: Json<Buckle>) -> Json<Buckle>;
    fn declassify(target_secrecy: Json<Component>) -> Json<Buckle>;
    fn dent_open(dent_open_json: Json<DentOpen>) -> Json<DentOpenResult>;
    fn dent_create(dent_create_json: Json<DentCreate>) -> Json<DentResult>;
    fn dent_close(input_fd: u64) -> Json<DentResult>;
    fn dent_update(dent_update_json: Json<DentUpdate>) -> Json<DentResult>;
    fn dent_read(fd: u64) -> Json<DentResult>;
}


#[plugin_fn]
pub fn run() -> FnResult<String> {
    unsafe {
        let Json(label1) = get_current_label().unwrap();
        let Json(label2) = buckle_parse("Dwaha,Dwaha").unwrap();
        let Json(label3) = taint_with_label(Json(label1.clone())).unwrap();//label2.clone().unwrap())).unwrap();
        let Json(label4) = get_current_label().unwrap();
        let Json(label5) = declassify(Json(Component::dc_true())).unwrap();

        let Json(create_result) = dent_create(Json(DentCreate{label: Some(Buckle::public()), kind: Some(dent_create::Kind::File)})).unwrap();
        let data = "hello, world".as_bytes().to_vec();
        let fd = create_result.fd.unwrap();
        let Json(update_result) = dent_update(Json(DentUpdate{fd, kind: Some(dent_update::Kind::File(data))})).unwrap();
        let Json(read_result) = dent_read(fd).unwrap();
        let Json(close_result) = dent_close(fd).unwrap();
        
        Ok(format!("1:{:#?}\n2:{:#?}\n3:{:#?}\n4:{:#?}\n5:{:#?}\n
            6: create result {:#?}\n7: update result {:#?}\n8: read result {:#?}\n9: close result {:#?}", 
            label1, 
            label2.unwrap(), 
            label3,
            label4,
            label5,
            create_result,
            update_result,
            read_result,
            close_result
        ))
    }
}

