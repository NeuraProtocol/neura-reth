# Reth QBFT Consensus

This crate provides QBFT (Quorum Byzantine Fault Tolerance) consensus implementation for Reth, allowing it to be used as an execution client for QBFT networks.

## Overview

QBFT is a consensus mechanism that provides:
- Finality through validator voting
- Byzantine fault tolerance
- Configurable validator sets
- Epoch-based validator rotation
- Block rewards for validators

## Configuration

### Configuration File

The recommended way to configure QBFT is using a TOML configuration file. Create a `config.toml` file with the following structure:

```toml
[qbft]
# Block period in seconds
block_period = 5

# Epoch length in blocks
epoch_length = 30000

# Validator set constraints
min_validators = 3
max_validators = 10

# Initial validator set (replace with your actual validator addresses)
validators = [
    "0x0101010101010101010101010101010101010101",
    "0x0202020202020202020202020202020202020202",
    "0x0303030303030303030303030303030303030303"
]

[qbft.rewards]
# Base reward in wei (2 ETH)
base_reward = "2000000000000000000"
# Multiplier for block proposer
proposer_multiplier = 2
# Multiplier for validators
validator_multiplier = 1
```

### Building the Executable

1. First, ensure you have Rust and Cargo installed. If not, install them using [rustup](https://rustup.rs/):
   ```bash
   curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
   ```

2. Clone the repository and navigate to the project directory:
   ```bash
   git clone https://github.com/paradigmxyz/reth.git
   cd reth
   ```

3. Build the QBFT node example:
   ```bash
   # Build in debug mode (faster compilation, slower execution)
   cargo build --example qbft-node

   # Build in release mode (slower compilation, faster execution)
   cargo build --release --example qbft-node
   ```

   The executable will be created at:
   - Debug build: `target/debug/examples/qbft-node`
   - Release build: `target/release/examples/qbft-node`

4. (Optional) Install the executable globally:
   ```bash
   cargo install --path . --example qbft-node
   ```

### Running the Node

1. Place your `config.toml` file in the same directory as your node executable or specify its path using the `--config` flag.

2. Run the node:
   ```bash
   # Using default config.toml in the current directory
   cargo run --example qbft-node

   # Using a specific configuration file
   cargo run --example qbft-node -- --config path/to/your/config.toml

   # If you installed globally, you can run it directly:
   qbft-node --config path/to/your/config.toml
   ```

### Storage and Snapshots

The QBFT node uses Reth's storage system, which includes:

1. **Database Storage**
   - Stores recent blocks and state
   - Maintains indexes and metadata
   - Handles active state management

2. **Static File Storage**
   - Stores historical data in an efficient format
   - Organized by segments (Headers, Transactions, Receipts, BlockMeta)
   - Automatically generates snapshots for historical data
   - Improves performance for historical queries

The node automatically manages both storage types:
- Recent data is kept in the database for fast access
- Historical data is moved to static files
- Snapshots are generated automatically as the chain progresses
- No manual snapshot management is required

### Configuration Parameters

#### QBFT Section

| Parameter | Description | Default |
|-----------|-------------|---------|
| `block_period` | Time between blocks in seconds | 5 |
| `validators` | Initial set of validator addresses | Required |
| `epoch_length` | Number of blocks in an epoch | 30000 |
| `min_validators` | Minimum number of validators | 3 |
| `max_validators` | Maximum number of validators | 10 |

#### Rewards Section

| Parameter | Description | Default |
|-----------|-------------|---------|
| `base_reward` | Base reward per block in wei | 2 ETH |
| `proposer_multiplier` | Multiplier for block proposer | 2 |
| `validator_multiplier` | Multiplier for validators | 1 |

## Features

### Validator Set Management
- Automatic validator rotation based on epochs
- Minimum and maximum validator constraints
- Validator set history tracking

### Block Validation
- Timestamp validation against block period
- Proposer validation
- Transaction validation
- No ommers (uncles) support

### Engine API Integration
- Payload validation
- Forkchoice state management
- Transition configuration handling

## Integration with Besu

To use Reth as an execution client with a Besu QBFT network:

1. Configure Besu with QBFT consensus
2. Configure Reth with matching chain parameters in your `config.toml`
3. Connect Reth to the Besu network
4. Reth will validate and execute blocks according to QBFT rules

## Security Considerations

- Ensure proper validator key management
- Configure appropriate minimum validator count
- Monitor validator set changes
- Implement proper reward distribution
- Keep your configuration file secure and backed up

## License

MIT OR Apache-2.0 