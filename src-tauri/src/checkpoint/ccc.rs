//! CCC S-expression codec — typed tree + hand-rolled recursive-descent parser,
//! serializer, and ergonomic accessors. Server input is untrusted: parsing is
//! bounded (length + nesting) and never panics; malformed input maps to
//! `VpnError::Protocol`. Never log field contents — they carry credentials in
//! later phases.
#![allow(dead_code)]

use crate::error::VpnError;

/// Largest CCC document we will parse (1 MiB). Guards against memory-exhaustion
/// on attacker-influenceable server frames (T-01-01).
const MAX_INPUT_LEN: usize = 1_048_576;
/// Maximum node nesting depth. Bounds recursion so a hostile deeply-nested frame
/// returns `Protocol` instead of overflowing the stack (T-01-01).
const MAX_DEPTH: usize = 64;

/// A parsed CCC S-expression value.
#[derive(Debug, Clone, PartialEq)]
pub enum CccValue {
    /// `()`
    Empty,
    /// `(600)` / `(UserPass)` — a bare token payload.
    Atom(String),
    /// `( :key value :key value ... )`, optionally led by a bare name token as in
    /// the top-level `(CCCserverResponse ...)`.
    Node {
        name: Option<String>,
        fields: Vec<(String, CccValue)>,
    },
}

impl CccValue {
    /// For a `Node`, return the value of the first field whose key matches `key`.
    pub fn get(&self, key: &str) -> Option<&CccValue> {
        match self {
            CccValue::Node { fields, .. } => {
                fields.iter().find(|(k, _)| k == key).map(|(_, v)| v)
            }
            _ => None,
        }
    }

    /// All field VALUES of a Node, in order — used to read S-expr arrays whose
    /// elements are written with the empty-key syntax `: (value)`. Non-Node → empty.
    pub fn elements(&self) -> Vec<&CccValue> {
        match self {
            CccValue::Node { fields, .. } => fields.iter().map(|(_, v)| v).collect(),
            _ => Vec::new(),
        }
    }

    /// The atom's string payload, if this is an `Atom`.
    pub fn as_atom(&self) -> Option<&str> {
        match self {
            CccValue::Atom(s) => Some(s.as_str()),
            _ => None,
        }
    }

    /// The node's name, if this is a named `Node`.
    pub fn name(&self) -> Option<&str> {
        match self {
            CccValue::Node { name, .. } => name.as_deref(),
            _ => None,
        }
    }

    /// Serialize back to re-parseable, tab-indented wire text (D-02). The contract
    /// is `parse(x.to_wire()) == x`, not byte-identity with the server.
    pub fn to_wire(&self) -> String {
        let mut out = String::new();
        self.write_indented(&mut out, 0);
        out
    }

    fn write_indented(&self, out: &mut String, depth: usize) {
        match self {
            CccValue::Empty => out.push_str("()"),
            CccValue::Atom(s) => {
                out.push('(');
                out.push_str(s);
                out.push(')');
            }
            CccValue::Node { name, fields } => {
                out.push('(');
                if let Some(n) = name {
                    out.push_str(n);
                }
                out.push('\n');
                for (k, v) in fields {
                    for _ in 0..depth + 1 {
                        out.push('\t');
                    }
                    out.push(':');
                    out.push_str(k);
                    out.push(' ');
                    v.write_indented(out, depth + 1);
                    out.push('\n');
                }
                for _ in 0..depth {
                    out.push('\t');
                }
                out.push(')');
            }
        }
    }
}

/// Parse a CCC document. The top-level form must be a single named node
/// `( Name ... )`. Untrusted input: bounded and panic-free; every malformed path
/// returns `VpnError::Protocol`.
pub fn parse(input: &str) -> Result<CccValue, VpnError> {
    if input.len() > MAX_INPUT_LEN {
        return Err(VpnError::Protocol("input too large".into()));
    }
    let chars: Vec<char> = input.chars().collect();
    let mut p = Parser { chars, pos: 0 };
    p.skip_ws();
    let value = p.parse_value(0)?;
    p.skip_ws();
    if p.pos != p.chars.len() {
        return Err(VpnError::Protocol("trailing data after document".into()));
    }
    match value {
        CccValue::Node { name: Some(_), .. } => Ok(value),
        _ => Err(VpnError::Protocol("document must be a named node".into())),
    }
}

struct Parser {
    chars: Vec<char>,
    pos: usize,
}

impl Parser {
    fn peek(&self) -> Option<char> {
        self.chars.get(self.pos).copied()
    }

    fn skip_ws(&mut self) {
        while let Some(c) = self.peek() {
            if c == ' ' || c == '\t' || c == '\r' || c == '\n' {
                self.pos += 1;
            } else {
                break;
            }
        }
    }

    /// Read a bare token (name/key/atom): any run of chars that are not whitespace,
    /// `(`, or `)`. May be empty; callers reject empty where required.
    fn read_token(&mut self) -> String {
        let mut s = String::new();
        while let Some(c) = self.peek() {
            if c == ' ' || c == '\t' || c == '\r' || c == '\n' || c == '(' || c == ')' {
                break;
            }
            s.push(c);
            self.pos += 1;
        }
        s
    }

    /// Parse a parenthesized value. `depth` is the current nesting level; entering
    /// a `(` increments it and trips `MAX_DEPTH`.
    fn parse_value(&mut self, depth: usize) -> Result<CccValue, VpnError> {
        if depth >= MAX_DEPTH {
            return Err(VpnError::Protocol("nesting too deep".into()));
        }
        match self.peek() {
            Some('(') => self.pos += 1,
            _ => return Err(VpnError::Protocol("expected '('".into())),
        }
        self.skip_ws();
        match self.peek() {
            None => Err(VpnError::Protocol("unexpected end of input".into())),
            Some(')') => {
                self.pos += 1;
                Ok(CccValue::Empty)
            }
            Some(':') => {
                let fields = self.parse_fields(depth + 1)?;
                Ok(CccValue::Node { name: None, fields })
            }
            Some(_) => {
                let token = self.read_token();
                if token.is_empty() {
                    return Err(VpnError::Protocol("expected token".into()));
                }
                self.skip_ws();
                match self.peek() {
                    Some(')') => {
                        self.pos += 1;
                        Ok(CccValue::Atom(token))
                    }
                    _ => {
                        let fields = self.parse_fields(depth + 1)?;
                        Ok(CccValue::Node {
                            name: Some(token),
                            fields,
                        })
                    }
                }
            }
        }
    }

    /// Parse `(':' key ws value)* ')'`. Assumes the opening `(` was already consumed.
    fn parse_fields(&mut self, depth: usize) -> Result<Vec<(String, CccValue)>, VpnError> {
        let mut fields = Vec::new();
        loop {
            self.skip_ws();
            match self.peek() {
                Some(')') => {
                    self.pos += 1;
                    return Ok(fields);
                }
                Some(':') => {
                    self.pos += 1;
                    // Consume the space in the `: (value)` array-element form before
                    // reading the key, so an element (empty key) parses correctly.
                    self.skip_ws();
                    let key = self.read_token();
                    // An empty key is allowed (array element `: (value)`). Malformed
                    // input is still rejected downstream by parse_value (e.g. `:)`
                    // yields "expected '('").
                    self.skip_ws();
                    let value = self.parse_value(depth)?;
                    fields.push((key, value));
                }
                None => return Err(VpnError::Protocol("unterminated node".into())),
                Some(_) => return Err(VpnError::Protocol("expected ':' or ')'".into())),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::VpnError;

    const SAMPLE: &str = "(CCCserverResponse :ResponseHeader ( :id () :type () :session_id () :return_code (504) ) :ResponseData () )";

    #[test]
    fn parses_live_504_sample() {
        let doc = parse(SAMPLE).expect("sample parses");
        assert_eq!(doc.name(), Some("CCCserverResponse"));
        let rc = doc
            .get("ResponseHeader")
            .and_then(|v| v.get("return_code"))
            .and_then(|v| v.as_atom());
        assert_eq!(rc, Some("504"));
        assert_eq!(doc.get("ResponseData"), Some(&CccValue::Empty));
        let hdr = doc.get("ResponseHeader").expect("header present");
        assert_eq!(hdr.get("id"), Some(&CccValue::Empty));
        assert_eq!(hdr.get("type"), Some(&CccValue::Empty));
        assert_eq!(hdr.get("session_id"), Some(&CccValue::Empty));
    }

    #[test]
    fn round_trip_reparse_stable() {
        let a = parse(SAMPLE).expect("parse a");
        let s = a.to_wire();
        let b = parse(&s).expect("parse b");
        assert_eq!(a, b);
    }

    #[test]
    fn malformed_returns_protocol_error() {
        for bad in ["(CCCserverResponse", "", "CCCserverResponse)", "()"] {
            match parse(bad) {
                Err(VpnError::Protocol(_)) => {}
                other => panic!("expected Protocol error for {bad:?}, got {other:?}"),
            }
        }
    }

    #[test]
    fn deeply_nested_input_does_not_panic() {
        let deep = "(".repeat(10_000);
        match parse(&deep) {
            Err(VpnError::Protocol(_)) => {}
            other => panic!("expected Protocol error, got {other:?}"),
        }
    }

    #[test]
    fn parses_atom_array_elements() {
        // `: (value)` empty-key array element syntax (RESEARCH §2b).
        let doc = parse("(dns_servers : (10.0.0.1) : (10.0.0.2))").expect("array parses");
        let els = doc.elements();
        assert_eq!(els.len(), 2);
        assert_eq!(els[0], &CccValue::Atom("10.0.0.1".into()));
        assert_eq!(els[1], &CccValue::Atom("10.0.0.2".into()));
    }

    #[test]
    fn parses_node_array_elements() {
        let doc = parse(
            "(range : (:from (10.0.0.0) :to (10.255.255.255)) : (:from (172.16.0.0) :to (172.16.255.255)))",
        )
        .expect("array of nodes parses");
        let els = doc.elements();
        assert_eq!(els.len(), 2);
        assert_eq!(
            els[0].get("from").and_then(|v| v.as_atom()),
            Some("10.0.0.0")
        );
        assert_eq!(
            els[0].get("to").and_then(|v| v.as_atom()),
            Some("10.255.255.255")
        );
        assert_eq!(
            els[1].get("from").and_then(|v| v.as_atom()),
            Some("172.16.0.0")
        );
    }

    #[test]
    fn elements_on_non_node_is_empty() {
        assert!(CccValue::Atom("x".into()).elements().is_empty());
        assert!(CccValue::Empty.elements().is_empty());
    }

    #[test]
    fn array_document_round_trips() {
        let src = "(range : (:from (10.0.0.0) :to (10.255.255.255)) : (:from (0.0.0.1) :to (0.0.0.1)))";
        let a = parse(src).expect("parse a");
        let b = parse(&a.to_wire()).expect("parse b");
        assert_eq!(a, b);
    }
}
