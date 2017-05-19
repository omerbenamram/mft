use std::collections::HashMap;
use rwinstructs::reference::{MftReference};

#[derive(Hash, Eq, PartialEq, Debug, Clone)]
pub struct PathMapping {
    pub name: String,
    pub parent: MftReference,
}

pub struct PathEnumerator {
    pub mapping: HashMap<MftReference,PathMapping>
}

impl PathEnumerator {
    pub fn new() -> PathEnumerator {
        PathEnumerator{
            mapping: HashMap::new()
        }
    }

    pub fn get_mapping(&self, reference: MftReference) -> Option<PathMapping> {
        match self.mapping.get(&reference) {
            Some(value) => Some(value.clone()),
            None => None
        }
    }

    pub fn print_mapping(&self){
        println!("{:?}",self.mapping);
    }

    pub fn contains_mapping(&self, reference: MftReference) -> bool {
        self.mapping.contains_key(
            &reference
        )
    }

    pub fn set_mapping(&mut self, reference: MftReference, mapping: PathMapping) {
        self.mapping.insert(
            reference,
            mapping
        );
    }
}
