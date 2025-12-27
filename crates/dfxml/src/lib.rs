//! Digital Forensics XML (DFXML) types and writers.
//!
//! This crate provides a small, schema-aligned subset of DFXML for use by the workspace tools.
//! Output is written using `quick-xml` to ensure well-formed XML and correct escaping.
//!
//! ## Schema reference
//!
//! This crate targets DFXML schema **2.0.0-beta.0** as published by the DFXML Working Group:
//!
//! - Reference repo (pinned): `external/refs/repos/dfxml-working-group__dfxml_schema.commit`
//! - Upstream: `https://github.com/dfxml-working-group/dfxml_schema`
//! - Local clone (for convenience): `external/refs/repos/dfxml-working-group__dfxml_schema/`
//!
//! The schema defines the namespace:
//!
//! - `http://www.forensicswiki.org/wiki/Category:Digital_Forensics_XML`
//!
//! and requires a `<dfxml>` root element with a `version` attribute, and a `<metadata>` child.
//!
//! ## Scope (intentionally small)
//!
//! We only implement the subset needed by this repository’s tools today:
//!
//! - `<dfxml>` root
//! - `<metadata>` with Dublin Core elements (e.g. `dc:type`)
//! - `<creator>` (program/version/build_environment/execution_environment)
//! - `<source>` (image_filename)
//! - `<diskimageobject>` with `<sector_size>` and `<byte_runs>/<byte_run>`
//! - `<hashdigest type="...">...</hashdigest>`
//!
//! Missing parts of the DFXML schema are not “best-effort”. Instead, callers should treat absent
//! types as “not supported yet” and either omit them or model them explicitly in this crate.

use std::borrow::Cow;

use quick_xml::Writer;
use quick_xml::events::{BytesDecl, BytesEnd, BytesStart, BytesText, Event};

/// DFXML XML namespace URI.
pub const DFXML_NS: &str = "http://www.forensicswiki.org/wiki/Category:Digital_Forensics_XML";

/// DFXML schema version targeted by this crate.
pub const DFXML_SCHEMA_VERSION: &str = "2.0.0-beta.0";

/// Dublin Core namespace URI.
pub const DC_NS: &str = "http://purl.org/dc/elements/1.1/";

#[derive(Debug, thiserror::Error)]
pub enum DfxmlError {
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Utf8(#[from] std::string::FromUtf8Error),
}

pub type Result<T> = std::result::Result<T, DfxmlError>;

/// A DFXML document.
#[derive(Debug, Clone, Default)]
pub struct DfxmlDocument {
    /// The schema version string placed in the root `dfxml@version` attribute.
    pub schema_version: Cow<'static, str>,

    pub metadata: Metadata,
    pub creator: Option<Creator>,
    pub source: Option<Source>,
    pub diskimageobjects: Vec<DiskImageObject>,
}

impl DfxmlDocument {
    pub fn new() -> Self {
        Self {
            schema_version: Cow::Borrowed(DFXML_SCHEMA_VERSION),
            metadata: Metadata::default(),
            creator: None,
            source: None,
            diskimageobjects: Vec::new(),
        }
    }

    pub fn to_xml_string(&self) -> Result<String> {
        let mut w = Writer::new_with_indent(Vec::new(), b'\t', 1);

        w.write_event(Event::Decl(BytesDecl::new("1.0", Some("UTF-8"), None)))?;
        w.write_event(Event::Text(BytesText::new("\n")))?;

        let mut root = BytesStart::new("dfxml");
        root.push_attribute(("xmlns", DFXML_NS));
        root.push_attribute(("xmlns:dc", DC_NS));
        root.push_attribute(("version", self.schema_version.as_ref()));
        w.write_event(Event::Start(root))?;

        self.metadata.write(&mut w)?;

        if let Some(c) = &self.creator {
            c.write(&mut w)?;
        }
        if let Some(s) = &self.source {
            s.write(&mut w)?;
        }
        for d in &self.diskimageobjects {
            d.write(&mut w)?;
        }

        w.write_event(Event::End(BytesEnd::new("dfxml")))?;
        w.write_event(Event::Text(BytesText::new("\n")))?;

        Ok(String::from_utf8(w.into_inner())?)
    }
}

/// DFXML metadata container.
///
/// In the schema, `<metadata>` is an “any”-container; this crate focuses on well-known Dublin Core
/// elements.
#[derive(Debug, Clone, Default)]
pub struct Metadata {
    pub dublin_core: Vec<DublinCoreElement>,
}

impl Metadata {
    fn write(&self, w: &mut Writer<Vec<u8>>) -> Result<()> {
        if self.dublin_core.is_empty() {
            w.write_event(Event::Empty(BytesStart::new("metadata")))?;
            return Ok(());
        }

        w.write_event(Event::Start(BytesStart::new("metadata")))?;
        for e in &self.dublin_core {
            e.write(w)?;
        }
        w.write_event(Event::End(BytesEnd::new("metadata")))?;
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct DublinCoreElement {
    pub name: DublinCoreElementName,
    pub value: String,
}

impl DublinCoreElement {
    fn write(&self, w: &mut Writer<Vec<u8>>) -> Result<()> {
        // Write as a namespaced element (e.g. `<dc:type>`).
        let tag = format!("dc:{}", self.name.as_str());
        w.write_event(Event::Start(BytesStart::new(tag.as_str())))?;
        w.write_event(Event::Text(BytesText::new(&self.value)))?;
        w.write_event(Event::End(BytesEnd::new(tag.as_str())))?;
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DublinCoreElementName {
    Title,
    Creator,
    Subject,
    Description,
    Publisher,
    Contributor,
    Date,
    Type,
    Format,
    Identifier,
    Source,
    Language,
    Relation,
    Coverage,
    Rights,
}

impl DublinCoreElementName {
    pub fn as_str(self) -> &'static str {
        match self {
            DublinCoreElementName::Title => "title",
            DublinCoreElementName::Creator => "creator",
            DublinCoreElementName::Subject => "subject",
            DublinCoreElementName::Description => "description",
            DublinCoreElementName::Publisher => "publisher",
            DublinCoreElementName::Contributor => "contributor",
            DublinCoreElementName::Date => "date",
            DublinCoreElementName::Type => "type",
            DublinCoreElementName::Format => "format",
            DublinCoreElementName::Identifier => "identifier",
            DublinCoreElementName::Source => "source",
            DublinCoreElementName::Language => "language",
            DublinCoreElementName::Relation => "relation",
            DublinCoreElementName::Coverage => "coverage",
            DublinCoreElementName::Rights => "rights",
        }
    }
}

/// DFXML creator block.
#[derive(Debug, Clone, Default)]
pub struct Creator {
    pub program: Option<String>,
    pub version: Option<String>,
    pub build_environment: Option<BuildEnvironment>,
    pub execution_environment: Option<ExecutionEnvironment>,
}

impl Creator {
    fn write(&self, w: &mut Writer<Vec<u8>>) -> Result<()> {
        w.write_event(Event::Start(BytesStart::new("creator")))?;

        if let Some(s) = &self.program {
            write_text_element(w, "program", s)?;
        }
        if let Some(s) = &self.version {
            write_text_element(w, "version", s)?;
        }
        if let Some(be) = &self.build_environment {
            be.write(w)?;
        }
        if let Some(ee) = &self.execution_environment {
            ee.write(w)?;
        }

        w.write_event(Event::End(BytesEnd::new("creator")))?;
        Ok(())
    }
}

#[derive(Debug, Clone, Default)]
pub struct BuildEnvironment {
    pub compiler: Option<String>,
    /// ISO-8601 xs:dateTime. If unknown, leave `None` (schema type is dateTime).
    pub compilation_date: Option<String>,
    pub libraries: Vec<Library>,
}

impl BuildEnvironment {
    fn write(&self, w: &mut Writer<Vec<u8>>) -> Result<()> {
        w.write_event(Event::Start(BytesStart::new("build_environment")))?;

        if let Some(s) = &self.compiler {
            write_text_element(w, "compiler", s)?;
        }
        if let Some(s) = &self.compilation_date {
            write_text_element(w, "compilation_date", s)?;
        }
        for lib in &self.libraries {
            lib.write(w)?;
        }

        w.write_event(Event::End(BytesEnd::new("build_environment")))?;
        Ok(())
    }
}

#[derive(Debug, Clone, Default)]
pub struct ExecutionEnvironment {
    pub os_sysname: Option<String>,
    pub arch: Option<String>,
}

impl ExecutionEnvironment {
    fn write(&self, w: &mut Writer<Vec<u8>>) -> Result<()> {
        w.write_event(Event::Start(BytesStart::new("execution_environment")))?;
        if let Some(s) = &self.os_sysname {
            write_text_element(w, "os_sysname", s)?;
        }
        if let Some(s) = &self.arch {
            write_text_element(w, "arch", s)?;
        }
        w.write_event(Event::End(BytesEnd::new("execution_environment")))?;
        Ok(())
    }
}

#[derive(Debug, Clone, Default)]
pub struct Library {
    pub name: Option<String>,
    pub version: Option<String>,
}

impl Library {
    fn write(&self, w: &mut Writer<Vec<u8>>) -> Result<()> {
        let mut el = BytesStart::new("library");
        if let Some(name) = &self.name {
            el.push_attribute(("name", name.as_str()));
        }
        if let Some(ver) = &self.version {
            el.push_attribute(("version", ver.as_str()));
        }
        w.write_event(Event::Empty(el))?;
        Ok(())
    }
}

#[derive(Debug, Clone, Default)]
pub struct Source {
    pub image_filenames: Vec<String>,
}

impl Source {
    fn write(&self, w: &mut Writer<Vec<u8>>) -> Result<()> {
        if self.image_filenames.is_empty() {
            return Ok(());
        }
        w.write_event(Event::Start(BytesStart::new("source")))?;
        for p in &self.image_filenames {
            write_text_element(w, "image_filename", p)?;
        }
        w.write_event(Event::End(BytesEnd::new("source")))?;
        Ok(())
    }
}

#[derive(Debug, Clone, Default)]
pub struct DiskImageObject {
    pub sector_size: Option<u64>,
    pub byte_runs: Vec<ByteRun>,
}

impl DiskImageObject {
    fn write(&self, w: &mut Writer<Vec<u8>>) -> Result<()> {
        w.write_event(Event::Start(BytesStart::new("diskimageobject")))?;

        if !self.byte_runs.is_empty() {
            w.write_event(Event::Start(BytesStart::new("byte_runs")))?;
            for br in &self.byte_runs {
                br.write(w)?;
            }
            w.write_event(Event::End(BytesEnd::new("byte_runs")))?;
        }

        if let Some(sector_size) = self.sector_size {
            write_text_element(w, "sector_size", &sector_size.to_string())?;
        }

        w.write_event(Event::End(BytesEnd::new("diskimageobject")))?;
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct ByteRun {
    pub img_offset: u64,
    pub len: u64,
    /// Optional `byte_run@type` attribute (string in schema).
    pub kind: Option<String>,
    pub hashdigests: Vec<HashDigest>,
}

impl ByteRun {
    fn write(&self, w: &mut Writer<Vec<u8>>) -> Result<()> {
        let mut el = BytesStart::new("byte_run");
        let off_s = self.img_offset.to_string();
        let len_s = self.len.to_string();
        el.push_attribute(("img_offset", off_s.as_str()));
        el.push_attribute(("len", len_s.as_str()));
        if let Some(kind) = &self.kind {
            el.push_attribute(("type", kind.as_str()));
        }

        if self.hashdigests.is_empty() {
            w.write_event(Event::Empty(el))?;
            return Ok(());
        }

        w.write_event(Event::Start(el))?;
        for h in &self.hashdigests {
            h.write(w)?;
        }
        w.write_event(Event::End(BytesEnd::new("byte_run")))?;
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct HashDigest {
    pub algorithm: HashDigestType,
    pub value: String,
}

impl HashDigest {
    fn write(&self, w: &mut Writer<Vec<u8>>) -> Result<()> {
        let mut el = BytesStart::new("hashdigest");
        el.push_attribute(("type", self.algorithm.as_str()));
        w.write_event(Event::Start(el))?;
        w.write_event(Event::Text(BytesText::new(&self.value)))?;
        w.write_event(Event::End(BytesEnd::new("hashdigest")))?;
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HashDigestType {
    Md5,
    Sha1,
}

impl HashDigestType {
    pub fn as_str(self) -> &'static str {
        match self {
            HashDigestType::Md5 => "md5",
            HashDigestType::Sha1 => "sha1",
        }
    }
}

fn write_text_element(w: &mut Writer<Vec<u8>>, name: &str, text: &str) -> std::io::Result<()> {
    w.write_event(Event::Start(BytesStart::new(name)))?;
    w.write_event(Event::Text(BytesText::new(text)))?;
    w.write_event(Event::End(BytesEnd::new(name)))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;
    use std::process::Command;

    #[test]
    fn test_minimal_dfxml_shape_matches_schema_example() {
        let doc = DfxmlDocument::new();
        let xml = doc.to_xml_string().unwrap();

        // Must have correct namespace and required version attribute.
        assert!(xml.contains("<dfxml"));
        assert!(xml.contains(DFXML_NS));
        assert!(xml.contains(&format!("version=\"{DFXML_SCHEMA_VERSION}\"")));

        // Must include metadata element.
        assert!(xml.contains("<metadata/>") || xml.contains("<metadata />"));
    }

    #[test]
    fn test_diskimageobject_byte_run_and_hashdigest_shape() {
        let mut doc = DfxmlDocument::new();
        doc.metadata.dublin_core.push(DublinCoreElement {
            name: DublinCoreElementName::Type,
            value: "Disk Image".to_string(),
        });
        doc.creator = Some(Creator {
            program: Some("ewfinfo".to_string()),
            version: Some("0.1.0".to_string()),
            build_environment: None,
            execution_environment: Some(ExecutionEnvironment {
                os_sysname: Some("macos".to_string()),
                arch: Some("aarch64".to_string()),
            }),
        });
        doc.source = Some(Source {
            image_filenames: vec!["image.E01".to_string()],
        });
        doc.diskimageobjects.push(DiskImageObject {
            sector_size: Some(512),
            byte_runs: vec![ByteRun {
                img_offset: 0,
                len: 1474560,
                kind: Some("image".to_string()),
                hashdigests: vec![
                    HashDigest {
                        algorithm: HashDigestType::Md5,
                        value: "deadbeef".to_string(),
                    },
                    HashDigest {
                        algorithm: HashDigestType::Sha1,
                        value: "cafebabe".to_string(),
                    },
                ],
            }],
        });

        let xml = doc.to_xml_string().unwrap();
        assert!(xml.contains("<diskimageobject>"));
        assert!(xml.contains("<sector_size>512</sector_size>"));
        assert!(xml.contains("<byte_runs>"));
        assert!(xml.contains("img_offset=\"0\""));
        assert!(xml.contains("len=\"1474560\""));
        assert!(xml.contains("type=\"image\""));
        assert!(xml.contains("<hashdigest type=\"md5\">deadbeef</hashdigest>"));
        assert!(xml.contains("<hashdigest type=\"sha1\">cafebabe</hashdigest>"));
    }

    #[test]
    fn test_xmllint_validates_output_against_vendored_schema_if_available() {
        // `xmllint` is available on macOS/Linux, but not guaranteed on Windows CI.
        let Ok(v) = Command::new("xmllint").arg("--version").output() else {
            return;
        };
        if !v.status.success() {
            return;
        }

        let doc = DfxmlDocument::new();
        let xml = doc.to_xml_string().unwrap();

        let dir = tempfile::tempdir().unwrap();
        let xml_path = dir.path().join("out.dfxml");
        std::fs::write(&xml_path, xml).unwrap();

        let schema_path = Path::new(env!("CARGO_MANIFEST_DIR")).join("schema/dfxml.xsd");

        let out = Command::new("xmllint")
            .arg("--noout")
            .arg("--schema")
            .arg(schema_path)
            .arg(&xml_path)
            .output()
            .unwrap();

        assert!(
            out.status.success(),
            "xmllint failed: {}\n{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
    }
}
