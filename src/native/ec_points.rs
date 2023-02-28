use std::{convert::TryInto, str::FromStr};

use fawkes_crypto::{ff_uint::Num, native::ecc::EdwardsPoint, BorshDeserialize};

use super::{params::PoolParams, cipher::buf_take};

#[derive(Serialize, Deserialize, PartialEq, Debug, Clone, Copy, Default)]
pub enum ECPointsFormat {
    #[default]
    XCoordinate,
    XCoordinateWithSign,
    XYCoordinates,
}

impl FromStr for ECPointsFormat {
    type Err = String;

    fn from_str(input: &str) -> Result<ECPointsFormat, Self::Err> {
        match input {
            "XCoordinate" => Ok(ECPointsFormat::XCoordinate),
            "XCoordinateWithSign" => Ok(ECPointsFormat::XCoordinateWithSign),
            "XYCoordinates" => Ok(ECPointsFormat::XYCoordinates),
            _ => Err("unknown format".to_string()),
        }
    }
}

pub(crate) fn parse_ec_point<'a, P: PoolParams>(
    memo: &mut &'a [u8],
    num_size: usize,
    params: &P,
    ec_points_format: ECPointsFormat,
) -> Option<EdwardsPoint<P::Fr>> {
    match ec_points_format {
        ECPointsFormat::XCoordinate => {
            EdwardsPoint::subgroup_decompress(Num::deserialize(memo).ok()?, params.jubjub())
        }
        ECPointsFormat::XCoordinateWithSign => {
            let bytes = buf_take(memo, num_size)?;
            EdwardsPoint::decompress_unchecked(bytes.try_into().ok()?, params.jubjub())
        }
        ECPointsFormat::XYCoordinates => {
            let point = EdwardsPoint {
                x: Num::deserialize(memo).ok()?,
                y: Num::deserialize(memo).ok()?,
            };
            if point.is_in_curve(params.jubjub()) {
                Some(point)
            } else {
                None
            }
        }
    }
}

pub(crate) fn skip_ec_point<'a>(
    memo: &mut &'a [u8],
    num_size: usize,
    ec_points_format: ECPointsFormat,
) -> Option<()> {
    match ec_points_format {
        ECPointsFormat::XYCoordinates => {
            buf_take(memo, num_size * 2)?;
        }
        _ => {
            buf_take(memo, num_size)?;
        }
    }
    Some(())
}

pub(crate) fn check_in_prime_subgroup<P: PoolParams>(
    p: EdwardsPoint<P::Fr>,
    params: &P,
    ec_points_format: ECPointsFormat,
) -> Option<()> {
    match ec_points_format {
        ECPointsFormat::XCoordinate => {
            // we've already checked it in subgroup_decompress
            Some(())
        }
        _ => p.is_in_prime_subgroup(params.jubjub()).then_some(()),
    }
}
