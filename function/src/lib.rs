use extism_pdk::*;
use labeled::buckle::{Buckle, Component};
use faasten_interface_types::{dent_create, dent_update, DentCreate, DentLink, DentListResult, 
    DentOpen, DentOpenResult, DentResult, DentUnlink, DentUpdate};

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
    fn dent_link(dent_link_json: Json<DentLink>) -> Json<DentResult>;
    fn dent_unlink(dent_unlink_json: Json<DentUnlink>) -> Json<DentResult>;
    fn dent_list(fd: u64) -> Json<DentListResult>;
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
        let file_fd = create_result.fd.unwrap();
        let Json(update_result) = dent_update(Json(DentUpdate{fd: file_fd, kind: Some(dent_update::Kind::File(data))})).unwrap();
        let Json(read_result) = dent_read(file_fd).unwrap();
        let Json(link_result1) = dent_link(Json(DentLink{dir_fd: 0, name: String::from("file1"), target_fd: file_fd})).unwrap();
        let Json(link_result2) = dent_link(Json(DentLink{dir_fd: 0, name: String::from("file1"), target_fd: file_fd})).unwrap();
        let Json(unlink_result) = dent_unlink(Json(DentUnlink{dir_fd:0, name: String::from("file1")})).unwrap();
        let Json(link_result3) = dent_link(Json(DentLink{dir_fd: 0, name: String::from("file1"), target_fd: file_fd})).unwrap();
        let Json(list_result1) = dent_list(0).unwrap();
        let Json(list_result2) = dent_list(file_fd).unwrap();
        let Json(close_result) = dent_close(file_fd).unwrap();
        
        Ok(format!("1:{:#?}\n2:{:#?}\n3:{:#?}\n4:{:#?}\n5:{:#?}
            \n6: create result {:#?}\n7: update result {:#?}\n8: read result {:#?}\n9: link result 1 {:#?}
            \n10: link result 2 {:#?}\n11: unlink result {:#?}\n12: link result 3 {:#?}
            \n13: list result 1 {:#?}\n14: list result 2 {:#?}\nclose result {:#?}", 
            label1, 
            label2.unwrap(), 
            label3,
            label4,
            label5,
            create_result,
            update_result,
            read_result,
            link_result1,
            link_result2,
            unlink_result,
            link_result3,
            list_result1,
            list_result2,
            close_result
        ))
    }
}

