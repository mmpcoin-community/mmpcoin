<h1 align="center">
<img src="https://mmpcoin.com/images/logo.png" data-canonical-src="https://mmpcoin.com/images/logo.png" width="250" height="250" alt="MmpCoin"/>
<br/><br/>
MmpCoin Core [MMP]
</h1>

<div align="center">

[![MmpCoinBadge](https://img.shields.io/badge/MmpCoin-Coin-blue)](https://dogecoin.com)
[![MuchWow](https://img.shields.io/badge/OG-Coin-yellow.svg)](https://dogecoin.com)

</div>

## This branch contains the latest version 2.0.0 of the mmpcoin network.

## What is MmpCoin?
MmpCoin is the twin of DogeCoin, born before it, and just seen the lights now. [Visit blockchain explorer](https://mmpcoin.com/)

## Development and contributions
Developers work in their own trees, then submit pull requests when they think
their feature or bug fix is ready.

## Usage 💻

To start your journey with MmpCoin Core, see the [installation guide](INSTALL.md) and the [getting started](doc/getting-started.md) tutorial.

The JSON-RPC API provided by MmpCoin Core is self-documenting and can be browsed with `mmpcoin-cli help`, while detailed information for each command can be viewed with `mmpcoin-cli help <command>`. Alternatively, see the [Bitcoin Core documentation](https://developer.bitcoin.org/reference/rpc/) - which implement a similar protocol - to get a browsable version.

## Frequently Asked Questions

### How much mmpcoin can exist?
Max supply of 1,000,000,000 coins with special rewards system.

### How to get $mmp?
Scrypt Proof of Work

1 Minute Block Targets, 20 minutes Diff Readjustments
### Block 1 (Pre-mining)
  * releases 200,000,000 coins for airdrop; specific rules will be updated on the official website later
### Less than 129600 blocks
  * Introducing the first phase release strategy of bellscoin
    * 50% chance of 50 coins    
    * 20% chance of 100 coins
    * 14% chance of 250 coins
    * 10% chance of 500 coins
    * 5% chance of 1000 coins
    * 1% chance of 10000 coins
### More than 129600 blocks
  * The release strategy employs a periodic parabolic reward pattern, with a base reward of 100 coins, reaching a peak of 300 coins within each 129,600 block cycle.
  * Introducing the luckcoin lucky block mechanism
    * 5% chance of getting regular coins + 188 coins (i.e. if regular coins are 100, you will get 288 coins)
    * 1% chance of getting regular coins + 588 coins
    * 0.01% chance of getting regular coins + 5888 coins

Halving at 129600 (~90 days)
After block 129600 (~6 year).

### Ports
| Function | mainnet | testnet | regtest |
| :------- |--------:| ------: | ------: |
| P2P      |   10320 |   10420 |   10520 |
| RPC      |   10319 |   10419 |   10519 |

## Change Log
### 0.7.0
- Updated to protocol 70001
- Added peer seeding

## License ⚖️
MmpCoin Core is released under the terms of the MIT license. See
[COPYING](COPYING) for more information or see
[opensource.org](https://opensource.org/licenses/MIT)
