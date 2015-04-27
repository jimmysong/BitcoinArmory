'''
Created on Aug 4, 2013

@author: Alan
'''
import sys
sys.path.append('..')
import unittest
import sys
sys.path.append('..')
import textwrap

from armoryengine.ArmoryUtils import *
from armoryengine.ArmoryEncryption import *

class MultiplierTest(unittest.TestCase):

   def testMultiplier3x(self):
      mult = []
      mult.append('\x11\xff'*16)
      mult.append('\x22\xee'*16)
      mult.append('\x33\xdd'*16)

      priv = '\x44\xcc'*16

      pubStart = CryptoECDSA().ComputePublicKey(SecureBinaryData(priv)).toBinStr()
      print 'Starting private key:', binary_to_hex(priv)
      print 'Starting public key: ', binary_to_hex(pubStart)
      print '  Multiplier 1:      ', binary_to_hex(mult[0])
      print '  Multiplier 2:      ', binary_to_hex(mult[1])
      print '  Multiplier 3:      ', binary_to_hex(mult[2])
      print 'ORDER:               ', int_to_hex(SECP256K1_ORDER, endOut=BIGENDIAN)


      intMult = [binary_to_int(m, BIGENDIAN) for m in mult]

      print ''
      print 'Mult3x, pre-multiply:   (a * b * c * priv) x G'
      newPriv = binary_to_int(priv, BIGENDIAN)
      newPriv = (newPriv * intMult[0]) % SECP256K1_ORDER
      newPriv = (newPriv * intMult[1]) % SECP256K1_ORDER
      newPriv = (newPriv * intMult[2]) % SECP256K1_ORDER

      privPreMult = SecureBinaryData(int_to_binary(newPriv, endOut=BIGENDIAN))
      pubPreMult  = CryptoECDSA().ComputePublicKey(privPreMult)
      print 'Resulting Priv:', privPreMult.toHexStr()
      print 'Resulting Pub: ', pubPreMult.toHexStr()


      print ''
      print 'Mult3x, post-multiply:  a x (b x (c x (priv x G)))'
      pubX = pubStart[1:33] 
      pubY = pubStart[  33:] 
      
      pubMult1 = CryptoECDSA().ECMultiplyPoint(mult[0], pubX, pubY)
      pubX = pubMult1[:32]
      pubY = pubMult1[ 32:]

      pubMult2 = CryptoECDSA().ECMultiplyPoint(mult[1], pubX, pubY)
      pubX = pubMult2[:32]
      pubY = pubMult2[ 32:]

      pubMult3 = CryptoECDSA().ECMultiplyPoint(mult[2], pubX, pubY)
      pubX = pubMult3[:32]
      pubY = pubMult3[ 32:]

      pubPostMult = SecureBinaryData('\x04' + pubX + pubY)
      print 'Resulting Pub: ', pubPostMult.toHexStr()

      print ''
      print 'PreX:  ', CryptoECDSA().CompressPoint(pubPreMult).toHexStr()
      print 'PostX: ', CryptoECDSA().CompressPoint(pubPostMult).toHexStr()

      print 'Match!' if pubPreMult == pubPostMult else 'FAILED!'
      self.assertEqual(pubPreMult.toHexStr(), pubPostMult.toHexStr())
      


if __name__ == "__main__":
   unittest.main()
