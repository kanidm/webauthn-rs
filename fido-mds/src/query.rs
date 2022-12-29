//! This implements a query language for the FIDO Metadata Service. This is loosely
//! based on the SCIM query language.
//!
//! `aaguid eq abcd and userverification eq passcodeexternal`

use std::str::FromStr;
use uuid::Uuid;

#[derive(Debug, PartialEq, Eq)]
pub enum CompareOp {
    Equal,
    NotEqual,
}

#[derive(Debug, PartialEq, Eq)]
pub enum AttrValueAssertion {
    Aaguid(Uuid),
}

#[derive(Debug, PartialEq, Eq)]
pub enum Query {
    Op(AttrValueAssertion, CompareOp),
    And(Box<Query>, Box<Query>),
    Or(Box<Query>, Box<Query>),
    Not(Box<Query>),
}

impl FromStr for Query {
    type Err = peg::error::ParseError<peg::str::LineCol>;

    fn from_str(q: &str) -> Result<Self, Self::Err> {
        query::parse(q)
    }
}

peg::parser! {
    grammar query() for str {
        pub rule parse() -> Query = precedence!{
                 a:(@) separator()+ "or" separator()+ b:@ {
                Query::Or(
                    Box::new(a),
                    Box::new(b)
                )
            }
            --
            a:(@) separator()+ "and" separator()+ b:@ {
                Query::And(
                    Box::new(a),
                    Box::new(b)
                )
            }
            --
            "not" separator()+ "(" e:parse() ")" {
                Query::Not(Box::new(e))
            }
            --
            "(" e:parse() ")" { e }
            a:expr() { a }
        }

        rule separator() =
            ['\n' | ' ' | '\t' ]

        rule operator() =
            ['\n' | ' ' | '\t' | '(' | ')' ]

        pub(crate) rule expr() -> Query =
            uuid_expr()

        rule uuid_expr() -> Query =
            "aaguid" separator()+ c:compareop() separator() + v:uuid() { Query::Op(AttrValueAssertion::Aaguid(v), c) }

        pub(crate) rule compareop() -> CompareOp =
            "eq" { CompareOp::Equal } /
            "ne" { CompareOp::NotEqual }

        pub(crate) rule uuid() -> Uuid =
            s:$((!operator()[_])*) {? Uuid::from_str(s).map_err(|_| "invalid UUID" ) }

    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_attr_uuid() {
        assert_eq!(
            query::uuid("c370f859-622e-4388-9ad2-a7fe7551fdba"),
            Ok(uuid::uuid!("c370f859-622e-4388-9ad2-a7fe7551fdba"))
        );
        assert!(query::uuid("oueuntonaeunaun").is_err());
    }

    #[test]
    fn test_compareop() {
        assert_eq!(query::compareop("eq"), Ok(CompareOp::Equal));
        assert_eq!(query::compareop("ne"), Ok(CompareOp::NotEqual));
    }

    #[test]
    fn test_query_attr_uuid() {
        assert_eq!(
            query::expr("aaguid eq c370f859-622e-4388-9ad2-a7fe7551fdba"),
            Ok(Query::Op(
                AttrValueAssertion::Aaguid(uuid::uuid!("c370f859-622e-4388-9ad2-a7fe7551fdba")),
                CompareOp::Equal
            ))
        );
    }

    #[test]
    fn test_query_not() {
        assert_eq!(
            query::parse("not (aaguid eq c370f859-622e-4388-9ad2-a7fe7551fdba)"),
            Ok(Query::Not(Box::new(Query::Op(
                AttrValueAssertion::Aaguid(uuid::uuid!("c370f859-622e-4388-9ad2-a7fe7551fdba")),
                CompareOp::Equal
            ))))
        );
    }

    #[test]
    fn test_query_and() {
        assert_eq!(
            query::parse("aaguid eq c370f859-622e-4388-9ad2-a7fe7551fdba and aaguid eq 70f11dce-befb-4619-a091-110633d923f6"),
            Ok(
                Query::And(
                    Box::new(
                        Query::Op(
                            AttrValueAssertion::Aaguid(uuid::uuid!("c370f859-622e-4388-9ad2-a7fe7551fdba")),
                            CompareOp::Equal
                        )
                    ),
                    Box::new(
                        Query::Op(
                            AttrValueAssertion::Aaguid(uuid::uuid!("70f11dce-befb-4619-a091-110633d923f6")),
                            CompareOp::Equal
                        )
                    ),
                )
            )
        );
    }

    #[test]
    fn test_query_or() {
        assert_eq!(
            query::parse("aaguid eq c370f859-622e-4388-9ad2-a7fe7551fdba or aaguid eq 70f11dce-befb-4619-a091-110633d923f6"),
            Ok(
                Query::Or(
                    Box::new(
                        Query::Op(
                            AttrValueAssertion::Aaguid(uuid::uuid!("c370f859-622e-4388-9ad2-a7fe7551fdba")),
                            CompareOp::Equal
                        )
                    ),
                    Box::new(
                        Query::Op(
                            AttrValueAssertion::Aaguid(uuid::uuid!("70f11dce-befb-4619-a091-110633d923f6")),
                            CompareOp::Equal
                        )
                    ),
                )
            )
        );
    }
}
