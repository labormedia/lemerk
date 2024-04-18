use core::ops::Add;
use crate::error::IndexError;
pub type CipherBlock = [u8;32];

#[derive(Debug, PartialEq, Clone, Copy, PartialOrd)]
pub struct Index(usize);

impl Index {
    pub fn from(value: usize) -> Index {
        Index(value)
    }
    pub fn get_index(&self) -> usize {
        self.0
    }
    pub fn incr(self) -> Index {
        self + Index::from(1)
    }
    pub fn try_decr(self) -> Result<Index, IndexError> {
        Ok(Index::from(self.get_index().checked_sub(1).ok_or(IndexError::IndexBadSubstraction)?) )
    }
    pub fn try_incr(self) -> Result<Index, IndexError> {
        Ok(Index::from(self.get_index().checked_add(1).ok_or(IndexError::IndexBadAddition)?) )
    }
    pub fn checked_rem(&self, value: usize) -> Result<Index, IndexError> {
        Ok(Index::from(self.get_index().checked_rem(value).ok_or(IndexError::IndexBadRemainder)?))
    }
}

impl Add for Index {
    type Output = Self;
    fn add(self, other: Self) -> Self {
        Index(self.get_index() + other.get_index())
    }
}

#[derive(Debug, PartialEq)]
pub struct DepthOffset(usize, usize);

impl DepthOffset {
    pub fn new(depth:usize, offset:usize) -> Self {
        DepthOffset(depth, offset)
    }
}

impl TryFrom<Index> for DepthOffset {
    type Error = IndexError;    
    // Incrementing from i = 0, 2_usize.pow(i) - 1 is always positive until OverFlow.
    // With an upper bound of value + 1, the condition "2_usize.pow(i) - 1 <= value.get_index() + 1" will always conform to false in the sequence 0..9223372036854775806 with step 1.
    // Unless value > 9223372036854775806.
    fn try_from(value: Index) -> Result<DepthOffset, Self::Error> {
        let value = value.get_index();
        if value < 9223372036854775806 { // The last possible level under usize precision is 63
            let mut i: u32 = 0;
            let mut acc: usize = 2_usize
                .checked_pow(i+1).ok_or(IndexError::IndexBadPow)?
                .checked_sub(1).ok_or(IndexError::IndexBadSubstraction)?;
            while value >= acc {
                i +=1;
                acc = 2_usize
                    .checked_pow(i+1).ok_or(
                        IndexError::IndexBadPow
                    )?
                    .checked_sub(1).ok_or(IndexError::IndexBadSubstraction)?;
            };
            let prev = 2_usize
                .checked_pow(i).ok_or(IndexError::IndexBadPow)?
                .checked_sub(1).ok_or(IndexError::IndexBadSubstraction)?;
            Ok(DepthOffset::from((i as usize, value-prev)))
        } else if value == 9223372036854775807 {
            Ok(DepthOffset::from((63, 0)))
        } else {
            let closest_log2 = value.ilog2();
            let previous_layers_cardinality: usize = 2_usize
                .checked_pow(closest_log2).ok_or(IndexError::IndexBadPow)?
                .checked_sub(1).ok_or(IndexError::IndexBadSubstraction)?;
            Ok(DepthOffset::from((closest_log2 as usize, value-previous_layers_cardinality)))
        }

    }
}

impl From<(usize, usize)> for DepthOffset {
    fn from(value: (usize, usize)) -> DepthOffset {
        DepthOffset(value.0, value.1)
    }
}

impl TryFrom<DepthOffset> for Index {
    type Error = IndexError;
    fn try_from(value: DepthOffset) -> Result<Index, Self::Error> {
        let DepthOffset(depth, offset) = value;
        if depth > 63 || (depth == 63 && offset > 9223372036854775808) {
            return Err(IndexError::IndexOverflow);
        };
        Ok(Index(
            2_usize
            .checked_pow(depth as u32).ok_or(Self::Error::IndexOverflow)?
            .checked_sub(1).ok_or(Self::Error::IndexOverflow)?
            .checked_add(offset).ok_or(Self::Error::IndexOverflow)?
        ))
    }
}

impl TryFrom<(usize, usize)> for Index {
    type Error = IndexError;
    fn try_from(value: (usize, usize)) -> Result<Index, Self::Error> {
        let depth_offset: DepthOffset = value.into();
        Index::try_from(depth_offset)
    }
}

#[test]
fn try_from_depthoffset_zero() {
    assert_eq!(Index::try_from((0,0)), Ok(Index(0)));
}

#[test]
fn try_from_depthoffset_5_4() {
    assert_eq!(Index::try_from((5,4)), Ok(Index(35)));
}

#[test]
fn half_usize() {
    assert_eq!((2_usize*9223372036854775807) + 1, usize::MAX);
}

#[test]
fn try_from_depthoffset_63_9223372036854775808() {
    assert_eq!(Index::try_from((63,9223372036854775808)).unwrap(), Index::from(usize::MAX));
}

#[test]
fn try_from_one_more_than_max() {
    assert_eq!(Index::try_from((63,9223372036854775808 + 1)).unwrap_err(), IndexError::IndexOverflow);
}

#[test]
fn try_from_depthoffset_64_0_overflow() {
    assert_eq!(Index::try_from((64,0)).unwrap_err(), IndexError::IndexOverflow);
}

#[test]
fn try_from_depthoffset_max_overflow() {
    assert_eq!(Index::try_from((usize::MAX,usize::MAX)).unwrap_err(), IndexError::IndexOverflow);
}

#[test]
fn try_from_index_to_depthoffset() {
    assert_eq!(DepthOffset::try_from(Index::from(0)).unwrap(), DepthOffset::new(0,0));
    assert_eq!(DepthOffset::try_from(Index::from(1)).unwrap(), DepthOffset::new(1,0));
    assert_eq!(DepthOffset::try_from(Index::from(2)).unwrap(), DepthOffset::new(1,1));
    assert_eq!(DepthOffset::try_from(Index::from(3)).unwrap(), DepthOffset::new(2,0));
    assert_eq!(DepthOffset::try_from(Index::from(4)).unwrap(), DepthOffset::new(2,1));
    assert_eq!(DepthOffset::try_from(Index::from(5)).unwrap(), DepthOffset::new(2,2));
    assert_eq!(DepthOffset::try_from(Index::from(6)).unwrap(), DepthOffset::new(2,3));
    assert_eq!(DepthOffset::try_from(Index::from(7)).unwrap(), DepthOffset::new(3,0));

    assert_eq!(DepthOffset::try_from(Index::from(16)).unwrap(), DepthOffset::new(4,1));
    assert_eq!(
        DepthOffset::try_from(
            Index::from(
                usize::MAX
                .checked_div(2).unwrap()
                .checked_sub(1).unwrap()
            )
        ).unwrap(), 
        DepthOffset::new(62,4611686018427387903)
    );
    assert_eq!(
        DepthOffset::try_from(
            Index::from(
                usize::MAX
            )
        ).unwrap(), 
        DepthOffset::new(63,9223372036854775808)
    );
}

#[test]
fn max_index_value_is_9223372036854775806() {
    assert_eq!(
        DepthOffset::try_from(Index::from(9223372036854775806)).unwrap()
        , 
        DepthOffset::new(62, 4611686018427387903)
    );
}

// These tests have been shortened for convenience.
#[test]
fn index_greater_than_9223372036854775806_are_valid() {
    let _: Vec<_> = (9223372036854775807..=9223372036854775807+100)
        .enumerate()
        .map( |(i,x)| {
            assert_eq!(
                DepthOffset::try_from(Index::from(x)).unwrap()
                , 
                DepthOffset::new(63, i)
            );
        })
        .collect();
}

#[test]
fn depthoffset_index_symmetry_small() {
    let x: usize = 0;
    let n_tests = 10000;
    let _: Vec<_> = (9223372036854775807..=9223372036854775807+n_tests)
        .enumerate()
        .map( |(i,x)| {
            assert_eq!(
                Index::from(x), 
                Index::try_from(DepthOffset::try_from(Index::from(x)).unwrap()).unwrap()
            );
        })
        .collect();
}

#[test]
fn depthoffset_index_symmetry_big() {
    let x: usize = 9223372036854775807;
    let n_tests = 10000;
    let _: Vec<_> = (9223372036854775807..=9223372036854775807+n_tests)
        .enumerate()
        .map( |(i,x)| {
            assert_eq!(
                Index::from(x), 
                Index::try_from(DepthOffset::try_from(Index::from(x)).unwrap()).unwrap()
            );
        })
        .collect();
}