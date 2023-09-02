use uuid::Uuid;

#[derive(Debug, PartialEq, Eq)]
pub enum Query {
    AaguidEqual(Uuid),
    AaguidNotEqual(Uuid),

    And(Box<Query>, Box<Query>),
    Or(Box<Query>, Box<Query>),
    Not(Box<Query>),
}
