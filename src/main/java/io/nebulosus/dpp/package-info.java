/**
 * The Data Persistence Protocol or DPP, is a protocol built on top of IPFS. This allows you to broadcast your data to
 * data-centers and storage providers in a way that allows them to provide persistence for you. At the end of the day
 * all of your data is encrypted before it is ever stored. The DPP utilizes private and public key crypto to identify
 * providers and clients. Each provider will generally have a relationship with the client. A trust is established in a
 * way that doesn't expose who is storing the data. Providers can accept any currency they would like and generally you
 * must trust the provider to store your data. At the end of the day it is up to you with what you do with your data.
 * The protocol works in a way that allows you to specify as many providers as you wish. Therefor your data could be
 * persisted forever.
 *
 * Cirrostratus is a P2P DPP provider that consists of hosts around the world both in public data-centers and private
 * data-centers. The Cirrostratus network allows your data to persist in a way that is nearly impossible to break. Honestly
 * I just made that up but we'll get there. Maybe we'll be able to prove that your data is stored or some shit.
 */
package io.nebulosus.dpp;