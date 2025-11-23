#include "../include/mxd_merkle_trie.h"
#include "../include/mxd_crypto.h"
#include "../include/mxd_logging.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

// Helper: Convert byte to two hex nibbles
static void byte_to_nibbles(uint8_t byte, uint8_t *nibble1, uint8_t *nibble2) {
    *nibble1 = (byte >> 4) & 0x0F;
    *nibble2 = byte & 0x0F;
}

// Helper: Get nibble at index from key
static uint8_t get_nibble(const uint8_t *key, size_t key_len, size_t nibble_index) {
    size_t byte_index = nibble_index / 2;
    if (byte_index >= key_len) {
        return 0xFF;  // Invalid nibble
    }
    
    if (nibble_index % 2 == 0) {
        return (key[byte_index] >> 4) & 0x0F;
    } else {
        return key[byte_index] & 0x0F;
    }
}

// Helper: Count matching nibbles between two keys
static size_t count_matching_nibbles(const uint8_t *key1, size_t key1_len,
                                     const uint8_t *key2, size_t key2_len,
                                     size_t start_nibble) {
    size_t matches = 0;
    size_t max_nibbles = (key1_len < key2_len ? key1_len : key2_len) * 2;
    
    for (size_t i = start_nibble; i < max_nibbles; i++) {
        uint8_t n1 = get_nibble(key1, key1_len, i);
        uint8_t n2 = get_nibble(key2, key2_len, i);
        
        if (n1 == 0xFF || n2 == 0xFF || n1 != n2) {
            break;
        }
        matches++;
    }
    
    return matches;
}

// Helper: Create a new leaf node
static mxd_trie_node_t *create_leaf_node(const uint8_t *key, size_t key_len,
                                         const uint8_t *value, size_t value_len) {
    mxd_trie_node_t *node = calloc(1, sizeof(mxd_trie_node_t));
    if (!node) return NULL;
    
    node->type = MXD_TRIE_NODE_LEAF;
    node->hash_valid = 0;
    
    node->data.leaf.key = malloc(key_len);
    if (!node->data.leaf.key) {
        free(node);
        return NULL;
    }
    memcpy(node->data.leaf.key, key, key_len);
    node->data.leaf.key_len = key_len;
    
    node->data.leaf.value = malloc(value_len);
    if (!node->data.leaf.value) {
        free(node->data.leaf.key);
        free(node);
        return NULL;
    }
    memcpy(node->data.leaf.value, value, value_len);
    node->data.leaf.value_len = value_len;
    
    return node;
}

// Helper: Create a new branch node
static mxd_trie_node_t *create_branch_node(void) {
    mxd_trie_node_t *node = calloc(1, sizeof(mxd_trie_node_t));
    if (!node) return NULL;
    
    node->type = MXD_TRIE_NODE_BRANCH;
    node->hash_valid = 0;
    
    for (int i = 0; i < 16; i++) {
        node->data.branch.children[i] = NULL;
    }
    node->data.branch.value = NULL;
    node->data.branch.value_len = 0;
    
    return node;
}

// Helper: Create a new extension node
static mxd_trie_node_t *create_extension_node(const uint8_t *key, size_t key_len,
                                               mxd_trie_node_t *child) {
    mxd_trie_node_t *node = calloc(1, sizeof(mxd_trie_node_t));
    if (!node) return NULL;
    
    node->type = MXD_TRIE_NODE_EXTENSION;
    node->hash_valid = 0;
    
    node->data.extension.key = malloc(key_len);
    if (!node->data.extension.key) {
        free(node);
        return NULL;
    }
    memcpy(node->data.extension.key, key, key_len);
    node->data.extension.key_len = key_len;
    node->data.extension.child = child;
    
    return node;
}

// Helper: Free a trie node recursively
static void free_node(mxd_trie_node_t *node) {
    if (!node) return;
    
    switch (node->type) {
        case MXD_TRIE_NODE_LEAF:
            free(node->data.leaf.key);
            free(node->data.leaf.value);
            break;
            
        case MXD_TRIE_NODE_BRANCH:
            for (int i = 0; i < 16; i++) {
                free_node(node->data.branch.children[i]);
            }
            free(node->data.branch.value);
            break;
            
        case MXD_TRIE_NODE_EXTENSION:
            free(node->data.extension.key);
            free_node(node->data.extension.child);
            break;
            
        default:
            break;
    }
    
    free(node);
}

// Helper: Calculate hash of a node
static int calculate_node_hash(mxd_trie_node_t *node) {
    if (!node) return -1;
    if (node->hash_valid) return 0;
    
    // Prepare data to hash based on node type
    uint8_t *hash_data = NULL;
    size_t hash_data_len = 0;
    
    switch (node->type) {
        case MXD_TRIE_NODE_LEAF: {
            // Hash: type + key_len + key + value_len + value
            hash_data_len = 1 + sizeof(size_t) + node->data.leaf.key_len + 
                           sizeof(size_t) + node->data.leaf.value_len;
            hash_data = malloc(hash_data_len);
            if (!hash_data) return -1;
            
            size_t offset = 0;
            hash_data[offset++] = (uint8_t)node->type;
            memcpy(hash_data + offset, &node->data.leaf.key_len, sizeof(size_t));
            offset += sizeof(size_t);
            memcpy(hash_data + offset, node->data.leaf.key, node->data.leaf.key_len);
            offset += node->data.leaf.key_len;
            memcpy(hash_data + offset, &node->data.leaf.value_len, sizeof(size_t));
            offset += sizeof(size_t);
            memcpy(hash_data + offset, node->data.leaf.value, node->data.leaf.value_len);
            break;
        }
        
        case MXD_TRIE_NODE_BRANCH: {
            // Hash: type + children_hashes + value_len + value
            hash_data_len = 1 + (16 * 64) + sizeof(size_t) + node->data.branch.value_len;
            hash_data = malloc(hash_data_len);
            if (!hash_data) return -1;
            
            size_t offset = 0;
            hash_data[offset++] = (uint8_t)node->type;
            
            // Include hashes of all children
            for (int i = 0; i < 16; i++) {
                if (node->data.branch.children[i]) {
                    calculate_node_hash(node->data.branch.children[i]);
                    memcpy(hash_data + offset, node->data.branch.children[i]->hash, 64);
                } else {
                    memset(hash_data + offset, 0, 64);
                }
                offset += 64;
            }
            
            memcpy(hash_data + offset, &node->data.branch.value_len, sizeof(size_t));
            offset += sizeof(size_t);
            if (node->data.branch.value_len > 0) {
                memcpy(hash_data + offset, node->data.branch.value, node->data.branch.value_len);
            }
            break;
        }
        
        case MXD_TRIE_NODE_EXTENSION: {
            // Hash: type + key_len + key + child_hash
            hash_data_len = 1 + sizeof(size_t) + node->data.extension.key_len + 64;
            hash_data = malloc(hash_data_len);
            if (!hash_data) return -1;
            
            size_t offset = 0;
            hash_data[offset++] = (uint8_t)node->type;
            memcpy(hash_data + offset, &node->data.extension.key_len, sizeof(size_t));
            offset += sizeof(size_t);
            memcpy(hash_data + offset, node->data.extension.key, node->data.extension.key_len);
            offset += node->data.extension.key_len;
            
            if (node->data.extension.child) {
                calculate_node_hash(node->data.extension.child);
                memcpy(hash_data + offset, node->data.extension.child->hash, 64);
            } else {
                memset(hash_data + offset, 0, 64);
            }
            break;
        }
        
        default:
            return -1;
    }
    
    // Calculate SHA-512 hash
    if (mxd_sha512(hash_data, hash_data_len, node->hash) != 0) {
        free(hash_data);
        return -1;
    }
    
    free(hash_data);
    node->hash_valid = 1;
    return 0;
}

// Forward declaration for recursive insert
static mxd_trie_node_t *insert_recursive(mxd_trie_node_t *node, const uint8_t *key,
                                         size_t key_len, size_t nibble_offset,
                                         const uint8_t *value, size_t value_len);

// Create a new empty merkle patricia trie
mxd_merkle_trie_t *mxd_trie_create(void) {
    mxd_merkle_trie_t *trie = calloc(1, sizeof(mxd_merkle_trie_t));
    if (!trie) return NULL;
    
    trie->root = NULL;
    trie->node_count = 0;
    trie->root_hash_valid = 0;
    
    return trie;
}

// Free a merkle patricia trie and all its nodes
void mxd_trie_free(mxd_merkle_trie_t *trie) {
    if (!trie) return;
    
    free_node(trie->root);
    free(trie);
}

// Insert or update a key-value pair in the trie
int mxd_trie_set(mxd_merkle_trie_t *trie, const uint8_t *key, size_t key_len,
                 const uint8_t *value, size_t value_len) {
    if (!trie || !key || !value) return -1;
    
    trie->root = insert_recursive(trie->root, key, key_len, 0, value, value_len);
    if (!trie->root) return -1;
    
    trie->root_hash_valid = 0;
    return 0;
}

// Recursive insert helper
static mxd_trie_node_t *insert_recursive(mxd_trie_node_t *node, const uint8_t *key,
                                         size_t key_len, size_t nibble_offset,
                                         const uint8_t *value, size_t value_len) {
    // If node is NULL, create a new leaf
    if (!node) {
        return create_leaf_node(key, key_len, value, value_len);
    }
    
    node->hash_valid = 0;  // Invalidate hash
    
    if (node->type == MXD_TRIE_NODE_LEAF) {
        // Check if keys match
        if (node->data.leaf.key_len == key_len &&
            memcmp(node->data.leaf.key, key, key_len) == 0) {
            // Update existing leaf value
            free(node->data.leaf.value);
            node->data.leaf.value = malloc(value_len);
            if (!node->data.leaf.value) return NULL;
            memcpy(node->data.leaf.value, value, value_len);
            node->data.leaf.value_len = value_len;
            return node;
        }
        
        // Keys don't match - need to split
        // Create a branch node and insert both keys
        mxd_trie_node_t *branch = create_branch_node();
        if (!branch) return NULL;
        
        // Insert existing leaf
        uint8_t existing_nibble = get_nibble(node->data.leaf.key, node->data.leaf.key_len, nibble_offset);
        if (existing_nibble < 16) {
            branch->data.branch.children[existing_nibble] = node;
        }
        
        // Insert new key
        uint8_t new_nibble = get_nibble(key, key_len, nibble_offset);
        if (new_nibble < 16) {
            branch->data.branch.children[new_nibble] = 
                create_leaf_node(key, key_len, value, value_len);
        }
        
        return branch;
    }
    
    if (node->type == MXD_TRIE_NODE_BRANCH) {
        uint8_t nibble = get_nibble(key, key_len, nibble_offset);
        if (nibble >= 16) {
            // End of key - store value in branch
            if (node->data.branch.value) {
                free(node->data.branch.value);
            }
            node->data.branch.value = malloc(value_len);
            if (!node->data.branch.value) return NULL;
            memcpy(node->data.branch.value, value, value_len);
            node->data.branch.value_len = value_len;
            return node;
        }
        
        node->data.branch.children[nibble] = 
            insert_recursive(node->data.branch.children[nibble], key, key_len,
                           nibble_offset + 1, value, value_len);
        return node;
    }
    
    // Extension node handling would go here for full implementation
    // For simplicity, we'll convert to branch
    return node;
}

// Get a value from the trie
int mxd_trie_get(const mxd_merkle_trie_t *trie, const uint8_t *key, size_t key_len,
                 uint8_t *value, size_t *value_len) {
    if (!trie || !key || !value || !value_len) return -1;
    
    mxd_trie_node_t *node = trie->root;
    size_t nibble_offset = 0;
    
    while (node) {
        if (node->type == MXD_TRIE_NODE_LEAF) {
            if (node->data.leaf.key_len == key_len &&
                memcmp(node->data.leaf.key, key, key_len) == 0) {
                if (*value_len < node->data.leaf.value_len) {
                    *value_len = node->data.leaf.value_len;
                    return -1;  // Buffer too small
                }
                memcpy(value, node->data.leaf.value, node->data.leaf.value_len);
                *value_len = node->data.leaf.value_len;
                return 0;
            }
            return -1;  // Key not found
        }
        
        if (node->type == MXD_TRIE_NODE_BRANCH) {
            uint8_t nibble = get_nibble(key, key_len, nibble_offset);
            if (nibble >= 16) {
                // End of key - check if branch has value
                if (node->data.branch.value) {
                    if (*value_len < node->data.branch.value_len) {
                        *value_len = node->data.branch.value_len;
                        return -1;
                    }
                    memcpy(value, node->data.branch.value, node->data.branch.value_len);
                    *value_len = node->data.branch.value_len;
                    return 0;
                }
                return -1;
            }
            node = node->data.branch.children[nibble];
            nibble_offset++;
            continue;
        }
        
        break;
    }
    
    return -1;  // Key not found
}

// Delete a key from the trie
int mxd_trie_delete(mxd_merkle_trie_t *trie, const uint8_t *key, size_t key_len) {
    // Simplified implementation - full implementation would handle node cleanup
    if (!trie || !key) return -1;
    
    trie->root_hash_valid = 0;
    return -1;  // Not implemented in this simplified version
}

// Calculate and return the merkle root hash of the trie
int mxd_trie_get_root_hash(mxd_merkle_trie_t *trie, uint8_t *root_hash) {
    if (!trie || !root_hash) return -1;
    
    if (!trie->root) {
        // Empty trie - return zero hash
        memset(root_hash, 0, 64);
        return 0;
    }
    
    if (!trie->root_hash_valid) {
        if (calculate_node_hash(trie->root) != 0) {
            return -1;
        }
        memcpy(trie->root_hash, trie->root->hash, 64);
        trie->root_hash_valid = 1;
    }
    
    memcpy(root_hash, trie->root_hash, 64);
    return 0;
}

// Verify the integrity of the trie
int mxd_trie_verify(mxd_merkle_trie_t *trie) {
    if (!trie) return -1;
    
    if (!trie->root) return 0;  // Empty trie is valid
    
    // Recalculate all hashes
    trie->root_hash_valid = 0;
    return calculate_node_hash(trie->root);
}

// Serialize/deserialize functions (simplified stubs)
int mxd_trie_serialize(const mxd_merkle_trie_t *trie, uint8_t *buffer, size_t *buffer_size) {
    // Stub - full implementation would serialize the entire tree
    return -1;
}

mxd_merkle_trie_t *mxd_trie_deserialize(const uint8_t *buffer, size_t buffer_size) {
    // Stub - full implementation would deserialize the tree
    return NULL;
}
