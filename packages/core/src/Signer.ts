import {
  addHexPrefix,
  fromSigned,
  toUnsigned,
  bigIntToBytes,
  hashPersonalMessage,
  intToHex,
} from '@ethereumjs/util'
import { TransactionFactory, TypedTxData } from '@ethereumjs/tx'
import { Common } from '@ethereumjs/common'
import { Wallets } from './Wallets'
import { UBuffer } from './Utils/UBuffer'

/**
 * The Signer class provides functionality to sign Ethereum transactions and messages using
 * private keys managed by a specified Wallets instance. It supports signing arbitrary messages,
 * hashed digests, and transaction data, preparing them for blockchain submission. The class
 * can be configured with a specific blockchain network through an optional chain ID, allowing
 * it to sign transactions according to network-specific parameters. It abstracts the complexities
 * of transaction serialization and signature generation, streamlining the process of creating
 * secure and valid blockchain transactions.
 */
export class Signer {
  wallets: Wallets
  common?: Common

  /**
   * Constructs a Signer instance with a specified Wallets instance and an optional chain ID.
   * The chain ID is used to configure the network for transactions.
   * @param wallets An instance of Wallets for key management and signing.
   * @param chainId Optional chain ID to specify the blockchain network.
   */
  constructor(wallets: Wallets, chainId?: number) {
    this.wallets = wallets
    this.common = chainId
      ? Common.custom({ chainId: chainId, networkId: chainId })
      : undefined
  }

  /**
   * Signs an Ethereum transaction with the specified account.
   * @param account An object containing the keyId and optional address of the signing account.
   * @param txData The transaction data to sign.
   * @returns A Promise that resolves to the serialized transaction as a '0x'-prefixed hex string.
   */
  public async signTransaction(
    account: { keyId: string; address?: Buffer },
    txData: TypedTxData
  ) {
    const tx = TransactionFactory.fromTxData(txData, { common: this.common })
    // `getHashedMessageToSign()` returns the 32-byte keccak-256 digest that the
    // signature must cover. `getMessageToSign()` returns the *unhashed* signing
    // payload instead - an array of RLP items for legacy transactions and the
    // serialized envelope for typed transactions - so signing that value would
    // produce a signature over the wrong bytes and an unusable transaction.
    const digestBuffer = Buffer.from(tx.getHashedMessageToSign())
    const { r, s, v } = await this.wallets.ecsign(
      account,
      digestBuffer,
      this.common?.chainId()
    )

    const signed = TransactionFactory.fromTxData(
      {
        ...txData,
        r: addHexPrefix(r.toString('hex')),
        s: addHexPrefix(s.toString('hex')),
        v: BigInt(v),
      },
      { common: this.common }
    )

    return addHexPrefix(Buffer.from(signed.serialize()).toString('hex'))
  }

  /**
   * Signs an arbitrary message using the specified account. The message is first
   * hashed and then signed.
   * @param account An object containing the keyId and optional address of the signing account.
   * @param message The message to sign.
   * @returns A Promise that resolves to the '0x'-prefixed hex string of the signature.
   */
  public async signMessage(
    account: { keyId: string; address?: Buffer },
    message: string
  ) {
    const digest = hashPersonalMessage(Buffer.from(message))
    return this.signDigest(account, Buffer.from(digest))
  }

  /**
   * Signs a digest (hashed message) using the specified account.
   * @param account An object containing the keyId and optional address of the signing account.
   * @param digest The digest to sign, either as a Buffer or a '0x'-prefixed hex string.
   * @returns A Promise that resolves to the '0x'-prefixed hex string of the signature.
   */
  public async signDigest(
    account: { keyId: string; address?: Buffer },
    digest: string | Buffer
  ) {
    const digestBuffer = UBuffer.bufferOrHex(digest)
    // secp256k1 signing operates on a 32-byte digest. Rejecting other lengths
    // stops a caller from accidentally handing a raw, unhashed message to the
    // signing key.
    if (digestBuffer.length !== 32) {
      throw new Error('Signer: digest must be exactly 32 bytes.')
    }
    const { r, s, v } = await this.wallets.ecsign(account, digestBuffer)

    // Convert to unsigned hex strings and pad to ensure consistent length (64 hex chars = 32 bytes)
    const rStr = Buffer.from(toUnsigned(fromSigned(r)))
      .toString('hex')
      .padStart(64, '0')
    const sStr = Buffer.from(toUnsigned(fromSigned(s)))
      .toString('hex')
      .padStart(64, '0')

    // Ensure v is cast to BigInt before converting to bytes, ensuring a 1-byte hex string (2 hex chars)
    const vBigInt = typeof v === 'bigint' ? v : BigInt(v)
    const vBytes = bigIntToBytes(vBigInt)
    const vStr = (vBytes.length === 0 ? '00' : Buffer.from(vBytes).toString('hex')).padStart(2, '0')

    // Concatenate the padded strings and add hex prefix
    return addHexPrefix(rStr.concat(sStr, vStr))
  }
}
