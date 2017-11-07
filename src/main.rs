#[macro_use] extern crate log;
extern crate env_logger;
extern crate rustymft;
extern crate rwinstructs;
extern crate serde_json;
extern crate jmespath;
extern crate serde;
extern crate clap;
use clap::{App, Arg, ArgMatches};
use rustymft::mft::{MftHandler};
use jmespath::{Expression};
use rwinstructs::reference;
use rwinstructs::serialize;
use serde::Serializer;
use serde::ser::SerializeSeq;
use std::fs;
use std::io;

fn process_directory(directory: &str, options: ArgMatches) {
    for entry in fs::read_dir(directory).unwrap() {
        let entry = entry.unwrap();
        let path = entry.path();
        if path.is_file() {
            let path_string = path.into_os_string().into_string().unwrap();
            if path_string.ends_with("mft"){
                process_file(&path_string,options.clone());
            }
        }
    }
}

fn process_file(filename: &str,options: ArgMatches) -> bool {
    // JMES Expression if needed
    let mut expr: Option<Expression> = None;
    if options.is_present("query") {
        expr = Some(jmespath::compile(
            options.value_of("query").unwrap()
        ).unwrap());
    }

    // Expression bool flag
    let mut expr_as_bool = false;
    if options.is_present("bool_expr"){
        expr_as_bool = true;
    }

    let mut mft_handler = match MftHandler::new(filename) {
        Ok(mft_handler) => mft_handler,
        Err(error) => {
            warn!("Could not parse file: {} [error: {}]", filename, error);
            return false;
        }
    };

    for i in 0 .. mft_handler.get_entry_count() {
        let mft_entry = match mft_handler.entry(i) {
            Ok(mft_entry) => {
                let json_str = serde_json::to_string(&mft_entry).unwrap();

                match expr {
                    Some(ref j_expr) => {
                        let data = jmespath::Variable::from_json(&json_str).unwrap();
                        let result = j_expr.search(data).unwrap();
                        if expr_as_bool {
                            match result.as_boolean() {
                                Some(bool_value) => {
                                    match bool_value {
                                        true => println!("{}",json_str),
                                        false => {}
                                    }
                                },
                                None => {
                                    panic!("Query expression is not a bool expression!");
                                }
                            }
                        } else {
                            println!("{}",result)
                        }
                    },
                    None => {
                        println!("{}",json_str);
                    }
                }
            },
            Err(error) => {
                error!("Could not mft_entry: {} [error: {}]", i, error);
                continue;
            }
        };
    }

    return true;
}

fn is_directory(source: &str)->bool{
    fs::metadata(source).unwrap().file_type().is_dir()
}

fn main() {
    env_logger::init().unwrap();
    let source_arg = Arg::with_name("source")
        .short("s")
        .long("source")
        .value_name("FILE")
        .help("The source path. Can be a file or a directory.")
        .required(true)
        .takes_value(true);

    let jmes_arg = Arg::with_name("query")
        .short("q")
        .long("query")
        .value_name("QUERY")
        .help("JMES Query")
        .takes_value(true);

    let bool_arg = Arg::with_name("bool_expr")
        .short("b")
        .long("bool_expr")
        .help("JMES Query as bool only. (Prints whole record if true.)");

    let options = App::new("RustyMft")
        .version("0.1.0")
        .author("Matthew Seyer <https://github.com/forensicmatt/RustyMft>")
        .about("Parse $MFT.")
        .arg(source_arg)
        .arg(jmes_arg)
        .arg(bool_arg)
        .get_matches();

    // Set Reference Display Options
    unsafe{reference::NESTED_REFERENCE = true;}
    unsafe{serialize::U64_SERIALIZATION = serialize::U64Serialization::AsString;}

    let source = options.value_of("source").unwrap();

    if is_directory(source) {
        panic!("Directory source is not implemented yet.");
    } else {
        process_file(source,options.clone());
    }
}
