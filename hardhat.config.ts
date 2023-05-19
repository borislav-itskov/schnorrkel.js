import { HardhatUserConfig } from 'hardhat/config'
require('@nomicfoundation/hardhat-toolbox')

const config: HardhatUserConfig = {
  solidity: {
    version: '0.8.18',
    settings: {
      viaIR: true,
      optimizer: {
        enabled: true,
        runs: 1000,
      },
    },
  },
}

export default config;