//! This implements a query language for the FIDO Metadata Service. This is loosely
//! based on the SCIM query language.
//!
//! `aaguid eq abcd and userverification eq passcodeexternal`

use crate::{AuthenticatorStatus, AuthenticatorTransport, UserVerificationMethod};
use std::str::FromStr;
use uuid::Uuid;

#[derive(Debug, PartialEq)]
pub enum AttrValueAssertion {
    AaguidEq(Uuid),
    DescriptionEq(String),
    DescriptionCnt(String),
    StatusEq(AuthenticatorStatus),
    StatusGte(AuthenticatorStatus),
    StatusLt(AuthenticatorStatus),
    TransportEq(AuthenticatorTransport),
    UserVerificationCnt(UserVerificationMethod),
}

#[derive(Debug, PartialEq)]
pub enum Query {
    Op(AttrValueAssertion),
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
            uuid_eq_expr() /
            desc_eq_expr() /
            desc_cn_expr() /
            authstat_eq_expr() /
            authstat_gte_expr() /
            authstat_lt_expr() /
            authtrans_eq_expr() /
            uvm_cnt_expr()

        rule uuid_eq_expr() -> Query =
            "aaguid" separator()+ "eq" separator()+ v:uuid() { Query::Op(AttrValueAssertion::AaguidEq(v)) }

        rule desc_eq_expr() -> Query =
            "desc" separator()+ "eq" separator()+ v:octetstr() { Query::Op(AttrValueAssertion::DescriptionEq(v)) }

        rule desc_cn_expr() -> Query =
            "desc" separator()+ "cnt" separator()+ v:octetstr() { Query::Op(AttrValueAssertion::DescriptionCnt(v)) }

        rule authstat_eq_expr() -> Query =
            "status" separator()+ "eq" separator()+ v:status() { Query::Op(AttrValueAssertion::StatusEq(v)) }

        rule authstat_gte_expr() -> Query =
            "status" separator()+ "gte" separator()+ v:status() { Query::Op(AttrValueAssertion::StatusGte(v)) }

        rule authstat_lt_expr() -> Query =
            "status" separator()+ "lt" separator()+ v:status() { Query::Op(AttrValueAssertion::StatusLt(v)) }

        rule authtrans_eq_expr() -> Query =
            "transport" separator()+ "eq" separator()+ v:transport() { Query::Op(AttrValueAssertion::TransportEq(v)) }

        rule uvm_cnt_expr() -> Query =
            "uvm" separator()+ "cnt" separator()+ v:uvm() { Query::Op(AttrValueAssertion::UserVerificationCnt(v)) }

        pub(crate) rule uuid() -> Uuid =
            s:$((!operator()[_])+) {? Uuid::from_str(s).map_err(|_| "invalid UUID" ) }

        pub(crate) rule status() -> AuthenticatorStatus =
            s:$((!operator()[_])+) {? AuthenticatorStatus::from_str(s).map_err(|_| "invalid Authenticator Status" ) }

        pub(crate) rule transport() -> AuthenticatorTransport =
            s:$((!operator()[_])+) {? AuthenticatorTransport::from_str(s).map_err(|_| "invalid Authenticator Transport" ) }

        pub(crate) rule uvm() -> UserVerificationMethod =
            s:$((!operator()[_])+) {? UserVerificationMethod::from_str(s).map_err(|_| "invalid User Verification Method" ) }

        pub(crate) rule octetstr() -> String =
            dquotedoctetstr() / squotedoctetstr() / bareoctetstr()

        rule squotedoctetstr() -> String =
            "\'" s:$((!"\'"[_])*) "\'" { s.to_string() }

        rule dquotedoctetstr() -> String =
            "\"" s:$((!"\""[_])*) "\"" { s.to_string() }

        rule bareoctetstr() -> String =
            s:$((!operator()[_])*) { s.to_string() }
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
    fn test_query_attr_uuid() {
        assert_eq!(
            query::expr("aaguid eq c370f859-622e-4388-9ad2-a7fe7551fdba"),
            Ok(Query::Op(AttrValueAssertion::AaguidEq(uuid::uuid!(
                "c370f859-622e-4388-9ad2-a7fe7551fdba"
            ))))
        );
    }

    #[test]
    fn test_query_not() {
        assert_eq!(
            query::parse("not (aaguid eq c370f859-622e-4388-9ad2-a7fe7551fdba)"),
            Ok(Query::Not(Box::new(Query::Op(
                AttrValueAssertion::AaguidEq(uuid::uuid!("c370f859-622e-4388-9ad2-a7fe7551fdba"))
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
                            AttrValueAssertion::AaguidEq(uuid::uuid!("c370f859-622e-4388-9ad2-a7fe7551fdba"))
                        )
                    ),
                    Box::new(
                        Query::Op(
                            AttrValueAssertion::AaguidEq(uuid::uuid!("70f11dce-befb-4619-a091-110633d923f6"))
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
                            AttrValueAssertion::AaguidEq(uuid::uuid!("c370f859-622e-4388-9ad2-a7fe7551fdba"))
                        )
                    ),
                    Box::new(
                        Query::Op(
                            AttrValueAssertion::AaguidEq(uuid::uuid!("70f11dce-befb-4619-a091-110633d923f6"))
                        )
                    ),
                )
            )
        );
    }
}
