use sha2::{Digest, Sha256};
use std::fmt;
use std::slice::Iter;
use thiserror::Error;
use hex;

// Errors reflecting invalid operations on a Merkle tree.
#[derive(Error, Debug)]
pub enum MerkleTreeError {
    #[error("merkle tree has not been finalized")]
    DirtyMerkleTree,
    #[error("merkle tree has been finalized")]
    NotDirtyMerkleTree,
    #[error("merkle tree has no data blocks")]
    EmptyMerkleTree,
    #[error("block cannot be nil")]
    NilBlock,
    #[error("block does not exist: {0}")]
    BlockNotFound(String),
    #[error("invalid proof at index {index} for block {block}; got: {got}, want: {want}")]
    InvalidProof {
        index: usize,
        block: String,
        got: String,
        want: String,
    },
}

const INTERNAL_NODE_PREFIX: u8 = 0x01;
const LEAF_NODE_PREFIX: u8 = 0x00;

// Type aliases for clarity
pub type Node = Vec<u8>;
pub type Block = Vec<u8>;

/// MerkleTree implements a binary complete Merkle tree data structure such
/// that every node is cryptographically hashed and is composed of the
/// hashes of its children. If a node has no child, it is the cryptographic
/// hash of a data block. A Merkle tree allows for efficient and secure
/// verification of the existence of data blocks that lead up to a secure
/// root hash. A data block is any arbitrary data structure that can be
/// interpreted as a byte slice such as chunks of a file.
///
/// Data blocks can be inserted into the Merkle tree in a given order where
/// the order is critical as it correlates to the construction of the root
/// hash. When the Merkle tree is ready to be constructed, it is "finalized"
/// such that the root hash is computed and proofs may be granted along with
/// verification of said proofs.
#[derive(Debug, Clone)]
pub struct MerkleTree {
    blocks: Vec<Block>,
    nodes: Vec<Node>,
    root: Option<Node>,
    dirty: bool,
}

impl MerkleTree {
    /// Creates a new Merkle tree with optional initial data blocks.
    pub fn new(blocks: Vec<Block>) -> Self {
        MerkleTree {
            blocks,
            nodes: Vec::new(),
            root: None,
            dirty: true,
        }
    }

    /// Inserts a new data block into the Merkle tree. This operation marks
    /// the tree as dirty, requiring finalization to recreate the root hash.
    /// Returns an error if the block is empty or the tree is not dirty.
    pub fn insert(&mut self, block: Block) -> Result<(), MerkleTreeError> {
        if block.is_empty() {
            return Err(MerkleTreeError::NilBlock);
        }

        if !self.dirty {
            return Err(MerkleTreeError::NotDirtyMerkleTree);
        }

        self.blocks.push(block);
        Ok(())
    }

    /// Returns the root hash of a finalized Merkle tree. Returns an error
    /// if the tree has not been finalized.
    pub fn root_hash(&self) -> Result<Node, MerkleTreeError> {
        if self.dirty {
            return Err(MerkleTreeError::DirtyMerkleTree);
        }

        Ok(self.root.as_ref().unwrap().clone())
    }

    /// Builds a SHA256 cryptographically hashed Merkle tree from a list of
    /// data blocks. If no blocks exist, an error is returned. Enforces the
    /// following invariants:
    ///
    /// - All leaf nodes and root node are encoded with a 0x00 byte prefix,
    ///   and all internal nodes with a 0x01 byte prefix to prevent second
    ///   pre-image attacks.
    /// - If there are an odd number of leaf nodes, the last data block is
    ///   duplicated to create an even set.
    pub fn finalize(&mut self) -> Result<(), MerkleTreeError> {
        if self.blocks.is_empty() {
            return Err(MerkleTreeError::EmptyMerkleTree);
        }

        if !self.dirty {
            return Ok(());
        }

        // Duplicate last block if odd number of blocks
        let mut blocks = self.blocks.clone();
        if blocks.len() % 2 == 1 {
            blocks.push(blocks.last().unwrap().clone());
        }

        // Allocate total number of nodes for a complete binary Merkle tree
        let node_count = 2 * blocks.len() - 1;
        self.nodes = vec![vec![]; node_count];

        // Set leaf nodes from blocks
        let mut j = node_count - blocks.len();
        for block in &blocks {
            self.nodes[j] = hash_node(block, false);
            j += 1;
        }

        // Build the tree and set the root
        self.root = Some(self.finalize_recursive(0));
        self.dirty = false;

        Ok(())
    }

    /// Recursively fills out the Merkle tree starting at a given node index.
    fn finalize_recursive(&self, node_idx: usize) -> Node {
        if !self.has_child(node_idx) {
            return self.nodes[node_idx].clone();
        }

        let left = self.finalize_recursive(2 * node_idx + 1);
        let right = self.finalize_recursive(2 * node_idx + 2);

        let mut combined = left;
        combined.extend_from_slice(&right);
        hash_node(&combined, true)
    }

    /// Returns a cryptographic Merkle proof for the existence of a block.
    /// Returns an error if the tree is dirty or the block does not exist.
    pub fn proof(&self, block: &Block) -> Result<Vec<Node>, MerkleTreeError> {
        if self.dirty {
            return Err(MerkleTreeError::DirtyMerkleTree);
        }

        let leaf_idx = self.find_leaf(block)?;
        let mut curr_node_idx = leaf_idx;
        let proof_size = (self.nodes.len() as f64).log2().ceil() as usize;
        let mut proof = Vec::with_capacity(proof_size);
        let mut k = 0;

        while curr_node_idx > 0 {
            // Add sibling to proof
            let sibling_idx = if curr_node_idx % 2 == 0 {
                curr_node_idx - 1
            } else {
                curr_node_idx + 1
            };
            proof.push(self.nodes[sibling_idx].clone());
            k += 1;

            // Move to parent
            curr_node_idx = (curr_node_idx - 1) / 2;
        }

        // Trim proof if last element is empty
        if proof.last().map_or(false, |n| n.is_empty()) {
            proof.pop();
        }

        Ok(proof)
    }

    /// Verifies a cryptographic Merkle proof for a given block.
    /// Returns an error if the proof is invalid or the block does not exist.
    pub fn verify(&self, block: &Block, proof: &[Node]) -> Result<(), MerkleTreeError> {
        if self.dirty {
            return Err(MerkleTreeError::DirtyMerkleTree);
        }

        let leaf_idx = self.find_leaf(block)?;
        let mut curr_node_idx = leaf_idx;

        for (i, proof_chunk) in proof.iter().enumerate() {
            let curr_node = &self.nodes[curr_node_idx];
            let mut combined = Vec::new();

            if curr_node_idx % 2 == 0 {
                combined.extend_from_slice(proof_chunk);
                combined.extend_from_slice(curr_node);
            } else {
                combined.extend_from_slice(curr_node);
                combined.extend_from_slice(proof_chunk);
            }

            let parent_node = hash_node(&combined, true);
            let parent_node_idx = (curr_node_idx - 1) / 2;

            if parent_node_idx < self.nodes.len() && self.nodes[parent_node_idx] != parent_node {
                return Err(MerkleTreeError::InvalidProof {
                    index: i,
                    block: hex::encode(block),
                    got: hex::encode(&parent_node),
                    want: hex::encode(&self.nodes[parent_node_idx]),
                });
            }

            curr_node_idx = parent_node_idx;
        }

        Ok(())
    }

    /// Finds the index of a leaf node corresponding to a given block.
    fn find_leaf(&self, block: &Block) -> Result<usize, MerkleTreeError> {
        let start_idx = self.nodes.len() - self.blocks.len();
        for (i, b) in self.blocks.iter().enumerate() {
            if b == block {
                return Ok(start_idx + i);
            }
        }
        Err(MerkleTreeError::BlockNotFound(hex::encode(block)))
    }

    /// Checks if a node at a given index has children.
    fn has_child(&self, node_idx: usize) -> bool {
        let left = 2 * node_idx + 1;
        let right = 2 * node_idx + 2;
        left < self.nodes.len() || right < self.nodes.len()
    }
}

impl fmt::Display for MerkleTree {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.root_hash() {
            Ok(hash) => write!(f, "0x{}", hex::encode(hash)),
            Err(_) => write!(f, ""),
        }
    }
}

/// Computes a SHA256 hash of data with a prefix based on whether the node is internal.
fn hash_node(data: &[u8], internal: bool) -> Node {
    let mut hasher = Sha256::new();
    if internal {
        hasher.update([INTERNAL_NODE_PREFIX]);
    } else {
        hasher.update([LEAF_NODE_PREFIX]);
    }
    hasher.update(data);
    hasher.finalize().to_vec()
}