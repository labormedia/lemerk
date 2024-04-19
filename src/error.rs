#[derive(Debug)]
pub enum LeMerkLevelError {
    Overflow,
}

#[derive(Debug, PartialEq)]
pub enum LeMerkTreeError {
    Overflow,
    BadDivision,
    BadMultiplication,
    BadAddition,
    BadSubstraction,
    BadPow,
}

pub enum VirtualNodeError {
    Overflow,
    BadDivision,
    BadMultiplication,
    BadAddition,
}

impl From<IndexError> for LeMerkTreeError {
    fn from(value: IndexError) -> LeMerkTreeError {
        match value {
            IndexError::IndexOverflow => LeMerkTreeError::Overflow,
            IndexError::IndexBadDivision => LeMerkTreeError::BadDivision,
            IndexError::IndexBadMultiplication => LeMerkTreeError::BadMultiplication,
            IndexError::IndexBadAddition => LeMerkTreeError::BadAddition,
            _ => panic!("Unexpected error"),
        }
    }
}

impl From<LeMerkLevelError> for LeMerkTreeError {
    fn from(value: LeMerkLevelError) -> LeMerkTreeError {
        match value {
            LeMerkLevelError::Overflow => LeMerkTreeError::Overflow,
            _ => panic!("Unexpected error"),
        }
    }
}

#[derive(Debug, PartialEq)]
pub enum IndexError {
    IndexOverflow,
    IndexBadDivision,
    IndexBadMultiplication,
    IndexBadAddition,
    IndexBadSubstraction,
    IndexBadRemainder,
    IndexBadPow,
    IndexBadilog,
}

#[derive(Debug)]
pub enum LeMerkBuilderError {
    Overflow,
    BadDivision,
    BadMultiplication,
    BadAddition,
    BadPow,
}

impl From<IndexError> for LeMerkBuilderError {
    fn from(value: IndexError) -> LeMerkBuilderError {
        match value {
            IndexError::IndexOverflow => LeMerkBuilderError::Overflow,
            IndexError::IndexBadDivision => LeMerkBuilderError::BadDivision,
            IndexError::IndexBadMultiplication => LeMerkBuilderError::BadMultiplication,
            IndexError::IndexBadAddition => LeMerkBuilderError::BadAddition,
            _ => panic!("Unexpected error"),
        }
    }
}