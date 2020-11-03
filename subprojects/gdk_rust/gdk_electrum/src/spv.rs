use log::warn;
use rand::seq::SliceRandom;
use serde::{Deserialize, Serialize};
use std::str::FromStr;

use bitcoin::blockdata::constants::{max_target, DIFFCHANGE_INTERVAL, DIFFCHANGE_TIMESPAN};
use bitcoin::BlockHash;
use bitcoin::{util::uint::Uint256, util::BitArray, BlockHeader};
use electrum_client::{Client as ElectrumClient, ElectrumApi};

use gdk_common::network::Network;

use crate::error::Error;
use crate::headers::bitcoin::HeadersChain;
use crate::interface::ElectrumUrl;

const INIT_CHUNK_SIZE: u32 = 5;
const MAX_CHUNK_SIZE: u32 = 200;
const MAX_FORK_DEPTH: u32 = DIFFCHANGE_INTERVAL * 3;
const SERVERS_PER_ROUND: usize = 3;

#[derive(Debug)]
pub struct SpvCrossValidator {
    servers: Vec<ElectrumUrl>,
    last_result: CrossValidationResult,
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub enum CrossValidationResult {
    Valid,

    // Our local chain is lagging behind a longer chain
    Lagging {
        our_height: u32,
        longest_height: u32,
        work_diff: Uint256,
        cross_server: ElectrumUrl,
    },

    // Our local chain is a lower-difficulty fork split off at `common_ancestor`
    MinorityFork {
        common_ancestor: u32,
        longest_height: u32,
        longest_work: Uint256, // the total work in the longest chain *since the common ancestor*
        work_diff: Uint256,
        cross_server: ElectrumUrl,
    },
}

// Indicates that the secondary server we cross-validated against is faulty,
// *not* an error with our primary server or local headers chain.
#[derive(Debug)]
pub enum CrossValidationError {
    IncompleteHeaders,
    InvalidHashChain,
    InvalidDifficulty,
    InvalidPow,
    InvalidRetarget,
    UnsensibleTarget,
    ForkDepthExceeded,
    KnownAncestorMismatch,
    GdkError(crate::error::Error),
    ElectrumError(electrum_client::Error),
}

impl_error_variant!(crate::error::Error, CrossValidationError, GdkError);
impl_error_variant!(electrum_client::Error, CrossValidationError, ElectrumError);

impl SpvCrossValidator {
    pub fn validate(&mut self, chain: &HeadersChain) -> CrossValidationResult {
        // Pick some random servers to cross-validate against for this round
        let mut round_servers = self.random_servers(SERVERS_PER_ROUND);

        // Clear the last failing result if our chain extended sufficiently to obsolete it,
        // but prioritize the server that reported it for an immediate re-check.
        if !self.last_result.is_valid() && self.last_result.is_resolved(chain) {
            round_servers.insert(0, self.last_result.server_origin().unwrap());
            self.last_result = CrossValidationResult::Valid;
        }

        let mut last_result = self.last_result.clone();
        let local_tip_hash = chain.tip().block_hash();

        // Cross-validate against the secondary servers, keeping track of the most severe
        // validation result seen so far
        for server_url in &round_servers {
            let server_result = match spv_cross_validate(chain, &local_tip_hash, server_url) {
                Ok(r) => r,
                Err(e) => {
                    warn!("SPV cross validation via {:?} failed with: {:?}", server_url, e);
                    continue;
                }
            };

            last_result = last_result.merge(server_result);
        }

        // Give some grace for minor digressions from the longest chain
        // XXX determine exact logic
        match last_result {
            CrossValidationResult::Lagging {
                longest_height,
                our_height,
                ..
            } if longest_height - our_height == 1 => {
                // Lagging behind the longest chain by 1 block
                last_result = CrossValidationResult::Valid;
            }
            _ => (),
        };

        self.last_result = last_result.clone();
        last_result
    }

    pub fn from_network(network: &Network) -> Result<Option<Self>, Error> {
        Ok(if !network.liquid && network.spv_cross_validation.unwrap_or(false) {
            Some(SpvCrossValidator {
                servers: get_network_servers(network)?,
                last_result: CrossValidationResult::Valid,
            })
        } else {
            None
        })
    }

    fn random_servers(&self, num: usize) -> Vec<ElectrumUrl> {
        let mut servers: Vec<_> = self.servers.iter().collect();
        servers.shuffle(&mut rand::thread_rng());
        servers.into_iter().take(num).cloned().collect()
    }
}

pub fn spv_cross_validate(
    chain: &HeadersChain,
    local_tip_hash: &BlockHash,
    server_url: &ElectrumUrl,
) -> Result<CrossValidationResult, CrossValidationError> {
    let client = server_url.build_client()?;
    let remote_tip = client.block_headers_subscribe()?;
    let remote_tip_hash = remote_tip.header.block_hash();
    let remote_tip_height = remote_tip.height as u32;

    // Both point to the same tip
    if remote_tip_height == chain.height() && remote_tip_hash == *local_tip_hash {
        return Ok(CrossValidationResult::Valid);
    }

    // The remote tip is lagging behind the local tip and can be fast-forwarded to it
    if chain.height() > remote_tip_height {
        let local_header = chain.get(remote_tip_height)?;
        if local_header.block_hash() == remote_tip_hash {
            return Ok(CrossValidationResult::Valid);
        }
    }

    // The local tip is lagging behind the remote tip and can be fast-forwarded to it
    if chain.height() < remote_tip_height {
        let remote_header = client.block_header(chain.height() as usize)?;
        if remote_header.block_hash() == *local_tip_hash {
            let fork = get_fork_branch(chain, &client, remote_tip_height, Some(chain.height()))?;

            return Ok(CrossValidationResult::Lagging {
                our_height: chain.height(),
                longest_height: fork.tip_height,
                work_diff: fork.total_fork_work,
                cross_server: server_url.clone(),
            });
        }
    }

    let fork = get_fork_branch(chain, &client, remote_tip_height, None)?;

    let our_work: Uint256 = (fork.common_ancestor + 1..=chain.height())
        .fold(Uint256::zero(), |total, height| total + chain.get(height).unwrap().work());

    // The remote is on a minority fork chain
    if fork.total_fork_work <= our_work {
        Ok(CrossValidationResult::Valid)
    }
    // We are on the minority fork
    else {
        Ok(CrossValidationResult::MinorityFork {
            longest_height: fork.tip_height,
            longest_work: fork.total_fork_work,
            common_ancestor: fork.common_ancestor,
            work_diff: fork.total_fork_work - our_work,
            cross_server: server_url.clone(),
        })
    }
}

struct ForkBranch {
    tip_height: u32,
    common_ancestor: u32,
    total_fork_work: Uint256,
}

/// Analyse the forked branch and return the common ancestor, the fork work and the fork tip height.
fn get_fork_branch(
    chain: &HeadersChain,
    client: &ElectrumClient,
    remote_tip_height: u32,
    known_ancestor: Option<u32>,
) -> Result<ForkBranch, CrossValidationError> {
    // A sensible target threshold used as anti-DoS while traversing blocks backwards. This is needed because
    // the exact expected target can only be determined later when reaching the period's first block.
    // Expects that all blocks involved in a reorg have a difficulty of at least 1/4 of our local tip.
    let sensible_target_threshold = chain.tip().target().mul_u32(4);

    // Will not reorg past that
    let height_limit = known_ancestor.unwrap_or(0);

    let mut total_fork_work = Uint256::zero();
    let mut curr_retarget: Option<(u32, BlockHeader, Option<BlockHeader>)> = None;
    let mut last_header: Option<BlockHeader> = None;

    let mut chunk_size = INIT_CHUNK_SIZE;
    let mut curr_height = remote_tip_height + 1;

    // Iterate over the remote headers from the tip backwards until we reach the common ancestor,
    // or until the fork depth limit is reached.
    'chunk_fetch: loop {
        let c_start = curr_height.saturating_sub(chunk_size).max(height_limit);
        let c_size = curr_height - c_start;
        let chunk = client.block_headers(c_start as usize, c_size as usize)?.headers;

        ensure!(chunk.len() == c_size as usize, CrossValidationError::IncompleteHeaders);

        for header in chunk.into_iter().rev() {
            let blockhash = header.block_hash();
            curr_height -= 1;
            let height = curr_height;

            let is_retarget = height % DIFFCHANGE_INTERVAL == 0;
            let is_period_first = height % DIFFCHANGE_INTERVAL == 1;
            let is_period_last = height % DIFFCHANGE_INTERVAL == DIFFCHANGE_INTERVAL - 1;

            // Verify that the last block we processed (which is the next block in the chain)
            // properly connects with the current block (its parent)
            if let Some(child) = last_header {
                ensure!(child.prev_blockhash == blockhash, CrossValidationError::InvalidHashChain);
                // Check that non-retarget blocks use the same difficulty as their parent.
                // Re-target blocks are checked separately below.
                ensure!(
                    is_period_last || child.bits == header.bits, // is_period_last indicates that our child is the retarget block
                    CrossValidationError::InvalidDifficulty
                );
            }

            // We reached the common ancestor
            if height <= chain.height() && chain.get(height)?.block_hash() == blockhash {
                break 'chunk_fetch;
            }

            // Fork depth exceeded without a common ancestor
            ensure!(
                remote_tip_height - height < MAX_FORK_DEPTH,
                CrossValidationError::ForkDepthExceeded
            );

            // Reached the expected common ancestor height (or the genesis block) and we still don't have a match
            ensure!(height > height_limit, CrossValidationError::KnownAncestorMismatch);

            // Verify the proof of work against the target specified by the header bits, and that its above
            // the sensible minimal threshold used as an anti-DoS measure. The validity of target is indirectly
            // verified later by comparing against the parent (above) and by validating the retargets (below).
            let target = header.target();
            ensure!(header.validate_pow(&target).is_ok(), CrossValidationError::InvalidPow);
            ensure!(target < sensible_target_threshold, CrossValidationError::UnsensibleTarget);

            // Verify retargets. Doing this as we go along backwards requires keeping around some state.
            match (is_retarget, is_period_last, is_period_first, &mut curr_retarget) {
                (true, _, _, curr_retarget) => {
                    *curr_retarget = Some((height, header.clone(), None))
                }
                (_, true, _, Some(curr_retarget)) => curr_retarget.2 = Some(header.clone()),
                (_, _, true, Some((_, retarget_block, period_last))) => {
                    verify_retarget(&retarget_block, &header, &period_last.unwrap())?; // period_last must exists if we got here
                    curr_retarget = None;
                }
                _ => (),
            }

            total_fork_work = total_fork_work + header.work();
            last_header = Some(header);
        }

        chunk_size = (chunk_size / 2 * 3).min(MAX_CHUNK_SIZE);
    }

    let common_ancestor = curr_height;

    // Sanity check, ensure the expected common ancestor matches the one we found
    if let Some(expected) = known_ancestor {
        ensure!(expected == common_ancestor, CrossValidationError::KnownAncestorMismatch);
    }

    // Verify the last pending retarget (if any) against our local headers chain
    if let Some((retarget_height, retarget_block, period_last)) = curr_retarget {
        let period_first = chain.get(retarget_height - DIFFCHANGE_INTERVAL)?;
        let period_last = period_last.map_or_else(|| chain.get(retarget_height - 1), Ok)?;
        verify_retarget(&retarget_block, &period_first, &period_last)?;
    }

    Ok(ForkBranch {
        tip_height: remote_tip_height,
        common_ancestor,
        total_fork_work,
    })
}

fn verify_retarget(
    retarget_block: &BlockHeader,
    period_first: &BlockHeader,
    period_last: &BlockHeader,
) -> Result<(), CrossValidationError> {
    let expected_target = calc_difficulty_retarget(period_first, period_last);
    ensure!(
        retarget_block.bits == BlockHeader::compact_target_from_u256(&expected_target),
        CrossValidationError::InvalidRetarget
    );
    Ok(())
}

pub fn calc_difficulty_retarget(first: &BlockHeader, last: &BlockHeader) -> Uint256 {
    let timespan = last.time - first.time;
    let timespan = timespan.min(DIFFCHANGE_TIMESPAN * 4);
    let timespan = timespan.max(DIFFCHANGE_TIMESPAN / 4);

    let new_target = last.target() * Uint256::from_u64(timespan as u64).unwrap()
        / Uint256::from_u64(DIFFCHANGE_TIMESPAN as u64).unwrap();

    new_target.min(max_target(bitcoin::Network::Bitcoin))
}

impl CrossValidationResult {
    // Check whether MinorityFork/Lagging validation results are still in effect,
    // based on the proof-of-work added to our local chain since the forking point
    fn is_resolved(&self, chain: &HeadersChain) -> bool {
        let local_work_since = |height| {
            (height..=chain.height())
                .fold(Uint256::zero(), |total, height| total + chain.get(height).unwrap().work())
        };
        match self {
            CrossValidationResult::Lagging {
                work_diff,
                our_height,
                ..
            } => local_work_since(our_height + 1) >= *work_diff,

            CrossValidationResult::MinorityFork {
                longest_work,
                common_ancestor,
                ..
            } => local_work_since(common_ancestor + 1) >= *longest_work,

            CrossValidationResult::Valid => true,
        }
    }

    // Merge the previous and current validation results, returning the most relevant/severe validation result
    fn merge(self, new_result: Self) -> Self {
        match (self, &new_result) {
            // Anything takes priority over Valid
            (CrossValidationResult::Valid, _) => new_result,

            // MinorityFork takes priority over Lagging
            (
                CrossValidationResult::Lagging {
                    ..
                },
                CrossValidationResult::MinorityFork {
                    ..
                },
            ) => new_result,

            // Prefer the Lagging result with the most extra work
            (
                CrossValidationResult::Lagging {
                    work_diff: curr_work,
                    ..
                },
                CrossValidationResult::Lagging {
                    work_diff: new_work,
                    ..
                },
            ) if *new_work > curr_work => new_result,

            // Prefer the MinorityFork result with the most extra work
            (
                CrossValidationResult::MinorityFork {
                    work_diff: curr_work,
                    ..
                },
                CrossValidationResult::MinorityFork {
                    work_diff: new_work,
                    ..
                },
            ) if *new_work > curr_work => new_result,

            // Otherwise, stick with what we have
            (curr, _) => curr,
        }
    }

    pub fn is_valid(&self) -> bool {
        match self {
            CrossValidationResult::Valid => true,
            _ => false,
        }
    }

    // Return the server that originated the validation result
    fn server_origin(&self) -> Option<ElectrumUrl> {
        match self {
            CrossValidationResult::Lagging {
                cross_server,
                ..
            }
            | CrossValidationResult::MinorityFork {
                cross_server,
                ..
            } => Some(cross_server.clone()),

            CrossValidationResult::Valid => None,
        }
    }
}

lazy_static! {
    static ref SERVER_LIST_MAINNET: Vec<ElectrumUrl> =
        parse_server_file(include_str!("servers-mainnet.txt"));
    static ref SERVER_LIST_TESTNET: Vec<ElectrumUrl> =
        parse_server_file(include_str!("servers-testnet.txt"));
}
fn parse_server_file(sl: &str) -> Vec<ElectrumUrl> {
    sl.lines().map(FromStr::from_str).collect::<Result<_, _>>().unwrap()
}

pub fn get_network_servers(network: &Network) -> Result<Vec<ElectrumUrl>, Error> {
    let net = network.id().get_bitcoin_network().expect("spv cross-validation is bitcoin-only");

    match &network.spv_cross_validation_servers {
        Some(servers) if !servers.is_empty() => {
            servers.iter().map(String::as_ref).map(FromStr::from_str).collect()
        }
        _ => Ok(match net {
            bitcoin::Network::Bitcoin => SERVER_LIST_MAINNET.clone(),
            bitcoin::Network::Testnet => SERVER_LIST_TESTNET.clone(),
            bitcoin::Network::Regtest => vec![],
        }),
    }
}
