//! Minimal proto2 wire codec (varint + length-delimited fields), as Wasabi's `TrezorProto`.

use std::collections::BTreeMap;

#[derive(Default, Clone)]
pub struct ProtoWriter {
    buf: Vec<u8>,
}

impl ProtoWriter {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn to_bytes(&self) -> Vec<u8> {
        self.buf.clone()
    }
    fn varint(&mut self, mut v: u64) {
        while v >= 0x80 {
            self.buf.push((v as u8) | 0x80);
            v >>= 7;
        }
        self.buf.push(v as u8);
    }
    pub fn varint_field(mut self, field: u32, v: u64) -> Self {
        self.varint((field as u64) << 3);
        self.varint(v);
        self
    }
    pub fn bool_field(self, field: u32, v: bool) -> Self {
        self.varint_field(field, v as u64)
    }
    pub fn bytes_field(mut self, field: u32, v: &[u8]) -> Self {
        self.varint(((field as u64) << 3) | 2);
        self.varint(v.len() as u64);
        self.buf.extend_from_slice(v);
        self
    }
    pub fn string_field(self, field: u32, v: &str) -> Self {
        self.bytes_field(field, v.as_bytes())
    }
    pub fn message_field(self, field: u32, m: &ProtoWriter) -> Self {
        self.bytes_field(field, &m.buf)
    }
    /// proto2 repeated scalars are unpacked.
    pub fn repeated_varint_field(mut self, field: u32, values: &[u32]) -> Self {
        for v in values {
            self = self.varint_field(field, *v as u64);
        }
        self
    }
}

#[derive(Debug, Clone, Default)]
pub struct Field {
    pub varint: u64,
    pub bytes: Vec<u8>,
}

pub type Fields = BTreeMap<u32, Vec<Field>>;

#[derive(Debug, thiserror::Error)]
#[error("malformed protobuf: {0}")]
pub struct ProtoError(&'static str);

fn read_varint(b: &[u8], pos: &mut usize) -> Result<u64, ProtoError> {
    let mut result = 0u64;
    let mut shift = 0;
    loop {
        let byte = *b.get(*pos).ok_or(ProtoError("truncated varint"))?;
        *pos += 1;
        result |= ((byte & 0x7f) as u64) << shift;
        if byte & 0x80 == 0 {
            return Ok(result);
        }
        shift += 7;
        if shift >= 64 {
            return Err(ProtoError("varint too long"));
        }
    }
}

pub fn read_fields(b: &[u8]) -> Result<Fields, ProtoError> {
    let mut fields: Fields = BTreeMap::new();
    let mut pos = 0;
    while pos < b.len() {
        let key = read_varint(b, &mut pos)?;
        let field = (key >> 3) as u32;
        let wire = key & 7;
        let f = match wire {
            0 => Field { varint: read_varint(b, &mut pos)?, bytes: vec![] },
            2 => {
                let len = read_varint(b, &mut pos)? as usize;
                let end = pos + len;
                let bytes = b.get(pos..end).ok_or(ProtoError("field past end"))?.to_vec();
                pos = end;
                Field { varint: 0, bytes }
            }
            5 => {
                pos += 4;
                Field::default()
            }
            1 => {
                pos += 8;
                Field::default()
            }
            _ => return Err(ProtoError("unsupported wire type")),
        };
        fields.entry(field).or_default().push(f);
    }
    Ok(fields)
}

pub fn first_varint(fields: &Fields, field: u32) -> Option<u64> {
    fields.get(&field).and_then(|v| v.first()).map(|f| f.varint)
}

pub fn first_bytes(fields: &Fields, field: u32) -> Option<&[u8]> {
    fields.get(&field).and_then(|v| v.first()).map(|f| f.bytes.as_slice())
}

pub fn first_string(fields: &Fields, field: u32) -> String {
    first_bytes(fields, field).map(|b| String::from_utf8_lossy(b).to_string()).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let w = ProtoWriter::new().varint_field(1, 300).string_field(2, "hi").repeated_varint_field(3, &[0x80000000, 5]).message_field(4, &ProtoWriter::new().bool_field(1, true));
        let f = read_fields(&w.to_bytes()).unwrap();
        assert_eq!(first_varint(&f, 1), Some(300));
        assert_eq!(first_string(&f, 2), "hi");
        assert_eq!(f[&3].iter().map(|x| x.varint).collect::<Vec<_>>(), vec![0x80000000, 5]);
        let inner = read_fields(first_bytes(&f, 4).unwrap()).unwrap();
        assert_eq!(first_varint(&inner, 1), Some(1));
    }
}
