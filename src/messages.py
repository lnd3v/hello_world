import base64
# from bitcoinlib.mnemonic import Mnemonic
# from bitcoinlib.keys import HDKey
from bip32utils import BIP32Key
from mnemonic import Mnemonic


WIF_PREFIX = 0xEF
ADD_PREFIX = 0x6F

"""A simple example of signing and verifying a message as in Bitcoin Core"""
import unittest
import base64
import wallycore as wally


class SignMessageTest(unittest.TestCase):
    WIF_PREFIX = 0xEF
    ADD_PREFIX = 0x6F

    def signmessage(self, priv_key, message):
        # priv_key = wif_to_bytes(
        #     priv_key_wif, self.WIF_PREFIX, WALLY_WIF_FLAG_COMPRESSED
        # )
        msg_fmt = wally.format_bitcoin_message(message, wally.BITCOIN_MESSAGE_FLAG_HASH)
        sig_bytes = wally.ec_sig_from_bytes(
            priv_key, msg_fmt, wally.EC_FLAG_ECDSA | wally.EC_FLAG_RECOVERABLE
        )
        return base64.b64encode(sig_bytes)

    def verifymessage(self, address, signature, message):
        msg_fmt = wally.format_bitcoin_message(message, wally.BITCOIN_MESSAGE_FLAG_HASH)
        sig_bytes = base64.b64decode(signature)
        pub_key_rec = wally.ec_sig_to_public_key(msg_fmt, sig_bytes)
        address_rec = wally.base58check_from_bytes(
            bytearray([self.ADD_PREFIX]) + wally.hash160(pub_key_rec)
        )
        return address == address_rec

    def test_signmessage(self):
        mnemonic = "cruise clever syrup coil cute execute laundry general cover prevent law sheriff"

        seed = Mnemonic.to_seed(mnemonic)

        master_key = BIP32Key.fromEntropy(seed)
        child_key = master_key.ChildKey(0).ChildKey(0)

        signature = self.signmessage(child_key.PrivateKey(), b'hello')
        print(signature)
        decoded = self.verifymessage(child_key.Address(), signature, b'hello')
        print(decoded)

unittest.main()
