use core::ops::Add;
pub type CipherBlock = [u8;32];

#[derive(Debug, PartialEq, Clone, Copy, PartialOrd)]
pub struct Index(usize);

#[derive(Debug, PartialEq)]
pub enum IndexError {
    IndexOverflow,
}

impl Index {
    pub fn from(value: usize) -> Index {
        Index(value)
    }
    pub fn get_index(&self) -> usize {
        self.0
    }
}

impl Add for Index {
    type Output = Self;
    fn add(self, other: Self) -> Self {
        Index(self.get_index() + other.get_index())
    }
}



pub struct DepthOffset(usize, usize);

impl DepthOffset {
    pub fn new(depth:usize, offset:usize) -> Self {
        DepthOffset(depth, offset)
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
fn try_from_depthoffset_max() {
    assert_eq!(Index::try_from((63,9223372036854775807 + 1)), Ok(Index(usize::MAX)));
}

#[test]
fn try_from_one_more_than_max() {
    assert_eq!(Index::try_from((63,9223372036854775807 + 2)).unwrap_err(), IndexError::IndexOverflow);
}

#[test]
fn try_from_depthoffset_64_0_overflow() {
    assert_eq!(Index::try_from((64,0)).unwrap_err(), IndexError::IndexOverflow);
}

#[test]
fn try_from_depthoffset_max_overflow() {
    assert_eq!(Index::try_from((usize::MAX,usize::MAX)).unwrap_err(), IndexError::IndexOverflow);
}