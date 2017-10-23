/**
 * The Evaporation Persistence Protocol or EPP, is a protocol built on top of IPFS. This allows you to broadcast your data to
 * data-centers and storage providers in a way that allows them to provide persistence in a p2p manner. At the end of the day
 * all of your data is encrypted before it is ever stored. The EPP utilizes private and public key crypto to identify
 * providers and peers. Each provider will generally have a relationship with the peer. A trust is established in a
 * way that doesn't expose who is storing the data. Providers can accept any currency they would like and generally you
 * must trust the provider to store your data. It is up to you with what you do with your data and who you want to store it.
 * The protocol works in a way that allows you to specify as many providers as you wish. Therefor your data could be
 * persisted forever and all over the world.
 *
 * Cirrostratus is a P2P EPP provider that consists of hosts around the world both in public data-centers and private
 * data-centers. The Cirrostratus network allows your data to persist in a way that is nearly impossible to break. Honestly
 * I just made that up but we'll get there. Maybe we'll be able to prove that your data is stored or something like that.
 */
package io.nebulosus.epp;