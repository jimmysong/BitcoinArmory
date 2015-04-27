################################################################################
#                                                                              #
# Copyright (C) 2011-2015, Armory Technologies, Inc.                           #
# Distributed under the GNU Affero General Public License (AGPL v3)            #
# See LICENSE or http://www.gnu.org/licenses/agpl.html                         #
#                                                                              #
################################################################################

from armoryengine.ArmoryUtils import *
from armoryengine.ArmoryEncryption import *
from armoryengine.ArmoryKeyPair import *
from armoryengine.WalletEntry import *


BIP32TestVectors = []

# 0
BIP32TestVectors.append( \
   {
      'seedKey': SecureBinaryData(hex_to_binary("00e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35")),
      'seedCC': SecureBinaryData(hex_to_binary("873dff81c02f525623fd1fe5167eac3a55a049de3d314bb42ee227ffed37d508")),
      'seedPubKey': SecureBinaryData(hex_to_binary("0439a36013301597daef41fbe593a02cc513d0b55527ec2df1050e2e8ff49c85c23cbe7ded0e7ce6a594896b8f62888fdbc5c8821305e2ea42bf01e37300116281")),
      'seedCompPubKey': SecureBinaryData(hex_to_binary("0339a36013301597daef41fbe593a02cc513d0b55527ec2df1050e2e8ff49c85c2")),
      'seedExtSerPrv': SecureBinaryData(hex_to_binary("0488ade4000000000000000000873dff81c02f525623fd1fe5167eac3a55a049de3d314bb42ee227ffed37d50800e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35")),
      'seedExtSerPub': SecureBinaryData(hex_to_binary("0488b21e000000000000000000873dff81c02f525623fd1fe5167eac3a55a049de3d314bb42ee227ffed37d5080339a36013301597daef41fbe593a02cc513d0b55527ec2df1050e2e8ff49c85c2")),
      'seedID': SecureBinaryData(hex_to_binary("3442193e1bb70916e914552172cd4e2dbc9df811")),
      'seedFP': SecureBinaryData(hex_to_binary("3442193e")),
      'seedParFP': SecureBinaryData(hex_to_binary("00000000")),
      'nextChild': 2147483648 
   })

# 1
BIP32TestVectors.append( \
   {
      'seedKey': SecureBinaryData(hex_to_binary("00edb2e14f9ee77d26dd93b4ecede8d16ed408ce149b6cd80b0715a2d911a0afea")),
      'seedCC': SecureBinaryData(hex_to_binary("47fdacbd0f1097043b78c63c20c34ef4ed9a111d980047ad16282c7ae6236141")),
      'seedPubKey': SecureBinaryData(hex_to_binary("045a784662a4a20a65bf6aab9ae98a6c068a81c52e4b032c0fb5400c706cfccc567f717885be239daadce76b568958305183ad616ff74ed4dc219a74c26d35f839")),
      'seedCompPubKey': SecureBinaryData(hex_to_binary("035a784662a4a20a65bf6aab9ae98a6c068a81c52e4b032c0fb5400c706cfccc56")),
      'seedExtSerPrv': SecureBinaryData(hex_to_binary("0488ade4013442193e8000000047fdacbd0f1097043b78c63c20c34ef4ed9a111d980047ad16282c7ae623614100edb2e14f9ee77d26dd93b4ecede8d16ed408ce149b6cd80b0715a2d911a0afea")),
      'seedExtSerPub': SecureBinaryData(hex_to_binary("0488b21e013442193e8000000047fdacbd0f1097043b78c63c20c34ef4ed9a111d980047ad16282c7ae6236141035a784662a4a20a65bf6aab9ae98a6c068a81c52e4b032c0fb5400c706cfccc56")),
      'seedID': SecureBinaryData(hex_to_binary("5c1bd648ed23aa5fd50ba52b2457c11e9e80a6a7")),
      'seedFP': SecureBinaryData(hex_to_binary("5c1bd648")),
      'seedParFP': SecureBinaryData(hex_to_binary("3442193e")),
      'nextChild': 1
   })

# 2
BIP32TestVectors.append( \
   {
      'seedKey': SecureBinaryData(hex_to_binary("003c6cb8d0f6a264c91ea8b5030fadaa8e538b020f0a387421a12de9319dc93368")),
      'seedCC': SecureBinaryData(hex_to_binary("2a7857631386ba23dacac34180dd1983734e444fdbf774041578e9b6adb37c19")),
      'seedPubKey': SecureBinaryData(hex_to_binary("04501e454bf00751f24b1b489aa925215d66af2234e3891c3b21a52bedb3cd711c008794c1df8131b9ad1e1359965b3f3ee2feef0866be693729772be14be881ab")),
      'seedCompPubKey': SecureBinaryData(hex_to_binary("03501e454bf00751f24b1b489aa925215d66af2234e3891c3b21a52bedb3cd711c")),
      'seedExtSerPrv': SecureBinaryData(hex_to_binary("0488ade4025c1bd648000000012a7857631386ba23dacac34180dd1983734e444fdbf774041578e9b6adb37c19003c6cb8d0f6a264c91ea8b5030fadaa8e538b020f0a387421a12de9319dc93368")),
      'seedExtSerPub': SecureBinaryData(hex_to_binary("0488b21e025c1bd648000000012a7857631386ba23dacac34180dd1983734e444fdbf774041578e9b6adb37c1903501e454bf00751f24b1b489aa925215d66af2234e3891c3b21a52bedb3cd711c")),
      'seedID': SecureBinaryData(hex_to_binary("bef5a2f9a56a94aab12459f72ad9cf8cf19c7bbe")),
      'seedFP': SecureBinaryData(hex_to_binary("bef5a2f9")),
      'seedParFP': SecureBinaryData(hex_to_binary("5c1bd648")),
      'nextChild': 2147483650
   })

# 3
BIP32TestVectors.append( \
   {
      'seedKey': SecureBinaryData(hex_to_binary("00cbce0d719ecf7431d88e6a89fa1483e02e35092af60c042b1df2ff59fa424dca")),
      'seedCC': SecureBinaryData(hex_to_binary("04466b9cc8e161e966409ca52986c584f07e9dc81f735db683c3ff6ec7b1503f")),
      'seedPubKey': SecureBinaryData(hex_to_binary("0457bfe1e341d01c69fe5654309956cbea516822fba8a601743a012a7896ee8dc24310ef3676384179e713be3115e93f34ac9a3933f6367aeb3081527ea74027b7")),
      'seedCompPubKey': SecureBinaryData(hex_to_binary("0357bfe1e341d01c69fe5654309956cbea516822fba8a601743a012a7896ee8dc2")),
      'seedExtSerPrv': SecureBinaryData(hex_to_binary("0488ade403bef5a2f98000000204466b9cc8e161e966409ca52986c584f07e9dc81f735db683c3ff6ec7b1503f00cbce0d719ecf7431d88e6a89fa1483e02e35092af60c042b1df2ff59fa424dca")),
      'seedExtSerPub': SecureBinaryData(hex_to_binary("0488b21e03bef5a2f98000000204466b9cc8e161e966409ca52986c584f07e9dc81f735db683c3ff6ec7b1503f0357bfe1e341d01c69fe5654309956cbea516822fba8a601743a012a7896ee8dc2")),
      'seedID': SecureBinaryData(hex_to_binary("ee7ab90cde56a8c0e2bb086ac49748b8db9dce72")),
      'seedFP': SecureBinaryData(hex_to_binary("ee7ab90c")),
      'seedParFP': SecureBinaryData(hex_to_binary("bef5a2f9")),
      'nextChild': 2
   })

# 4
BIP32TestVectors.append( \
   {
      'seedKey': SecureBinaryData(hex_to_binary("000f479245fb19a38a1954c5c7c0ebab2f9bdfd96a17563ef28a6a4b1a2a764ef4")),
      'seedCC': SecureBinaryData(hex_to_binary("cfb71883f01676f587d023cc53a35bc7f88f724b1f8c2892ac1275ac822a3edd")),
      'seedPubKey': SecureBinaryData(hex_to_binary("04e8445082a72f29b75ca48748a914df60622a609cacfce8ed0e35804560741d292728ad8d58a140050c1016e21f285636a580f4d2711b7fac3957a594ddf416a0")),
      'seedCompPubKey': SecureBinaryData(hex_to_binary("02e8445082a72f29b75ca48748a914df60622a609cacfce8ed0e35804560741d29")),
      'seedExtSerPrv': SecureBinaryData(hex_to_binary("0488ade404ee7ab90c00000002cfb71883f01676f587d023cc53a35bc7f88f724b1f8c2892ac1275ac822a3edd000f479245fb19a38a1954c5c7c0ebab2f9bdfd96a17563ef28a6a4b1a2a764ef4")),
      'seedExtSerPub': SecureBinaryData(hex_to_binary("0488b21e04ee7ab90c00000002cfb71883f01676f587d023cc53a35bc7f88f724b1f8c2892ac1275ac822a3edd02e8445082a72f29b75ca48748a914df60622a609cacfce8ed0e35804560741d29")),
      'seedID': SecureBinaryData(hex_to_binary("d880d7d893848509a62d8fb74e32148dac68412f")),
      'seedFP': SecureBinaryData(hex_to_binary("d880d7d8")),
      'seedParFP': SecureBinaryData(hex_to_binary("ee7ab90c")),
      'nextChild': 1000000000
   })

# 5
BIP32TestVectors.append( \
   {
      'seedKey': SecureBinaryData(hex_to_binary("00471b76e389e528d6de6d816857e012c5455051cad6660850e58372a6c3e6e7c8")),
      'seedCC': SecureBinaryData(hex_to_binary("c783e67b921d2beb8f6b389cc646d7263b4145701dadd2161548a8b078e65e9e")),
      'seedPubKey': SecureBinaryData(hex_to_binary("042a471424da5e657499d1ff51cb43c47481a03b1e77f951fe64cec9f5a48f7011cf31cb47de7ccf6196d3a580d055837de7aa374e28c6c8a263e7b4512ceee362")),
      'seedCompPubKey': SecureBinaryData(hex_to_binary("022a471424da5e657499d1ff51cb43c47481a03b1e77f951fe64cec9f5a48f7011")),
      'seedExtSerPrv': SecureBinaryData(hex_to_binary("0488ade405d880d7d83b9aca00c783e67b921d2beb8f6b389cc646d7263b4145701dadd2161548a8b078e65e9e00471b76e389e528d6de6d816857e012c5455051cad6660850e58372a6c3e6e7c8")),
      'seedExtSerPub': SecureBinaryData(hex_to_binary("0488b21e05d880d7d83b9aca00c783e67b921d2beb8f6b389cc646d7263b4145701dadd2161548a8b078e65e9e022a471424da5e657499d1ff51cb43c47481a03b1e77f951fe64cec9f5a48f7011")),
      'seedID': SecureBinaryData(hex_to_binary("d69aa102255fed74378278c7812701ea641fdf32")),
      'seedFP': SecureBinaryData(hex_to_binary("d69aa102")),
      'seedParFP': SecureBinaryData(hex_to_binary("d880d7d8")),
      'nextChild': None
   })

################################################################################
"""
We already have test vectors for the underlying C++ code, but we want to
check that they work when fully integrated into the wallet file.  This 
simply defines a chain of classes for which "fillKeyPool" generates the 
exact chain of ABEK objects.  

There's easier ways to compute M/0'/1/2'/2 with armoryengine, but this 
will serve as a test/demo for defining new key trees as well as the 
specific test itself.
"""
################################################################################

#############################################################################
class BIP32_TESTVECT_0(ArmoryBip32Seed):
   FILECODE = 'TESTVEC0'
   TREELEAF  = False
   HARDCHILD = True

   def __init__(self):
      super(BIP32_TESTVECT_0, self).__init__()
      self.isAkpRootRoot=True

   def getChildClass(self, index):
         return BIP32_TESTVECT_1

   def fillKeyPool(self, fsync=True, progressUpdater=emptyFunc):
      # All these test classes only have a single child, not really a keypool...
      indexToUse = CreateChildIndex(0, isHardened=self.HARDCHILD)
      newAkp = self.spawnChild(indexToUse, fsync=fsync, linkToParent=True)
      newAkp.fillKeyPool(fsync=fsync, progressUpdater=progressUpdater)


#############################################################################
class BIP32_TESTVECT_1(ArmoryBip32ExtendedKey):
   FILECODE = 'TESTVEC1'
   TREELEAF  = False
   HARDCHILD = False

   def __init__(self):
      super(BIP32_TESTVECT_1, self).__init__()

   def getChildClass(self, index):
         return BIP32_TESTVECT_2

   def fillKeyPool(self, fsync=True, progressUpdater=emptyFunc):
      indexToUse = CreateChildIndex(1, isHardened=self.HARDCHILD)
      newAkp = self.spawnChild(indexToUse, fsync=fsync, linkToParent=True)
      newAkp.fillKeyPool(fsync=fsync, progressUpdater=progressUpdater)


#############################################################################
class BIP32_TESTVECT_2(ArmoryBip32ExtendedKey):
   FILECODE = 'TESTVEC2'
   TREELEAF  = False
   HARDCHILD = True

   def __init__(self):
      super(BIP32_TESTVECT_2, self).__init__()

   def getChildClass(self, index):
         return BIP32_TESTVECT_3

   def fillKeyPool(self, fsync=True, progressUpdater=emptyFunc):
      indexToUse = CreateChildIndex(2, isHardened=self.HARDCHILD)
      newAkp = self.spawnChild(indexToUse, fsync=fsync, linkToParent=True)
      newAkp.fillKeyPool(fsync=fsync, progressUpdater=progressUpdater)



#############################################################################
class BIP32_TESTVECT_3(ArmoryBip32ExtendedKey):
   FILECODE = 'TESTVEC3'
   TREELEAF  = False
   HARDCHILD = False

   def __init__(self):
      super(BIP32_TESTVECT_3, self).__init__()

   def getChildClass(self, index):
         return BIP32_TESTVECT_4

   def fillKeyPool(self, fsync=True, progressUpdater=emptyFunc):
      indexToUse = CreateChildIndex(2, isHardened=self.HARDCHILD)
      newAkp = self.spawnChild(indexToUse, fsync=fsync, linkToParent=True)
      newAkp.fillKeyPool(fsync=fsync, progressUpdater=progressUpdater)


#############################################################################
class BIP32_TESTVECT_4(ArmoryBip32ExtendedKey):
   FILECODE = 'TESTVEC4'
   TREELEAF  = False
   HARDCHILD = False

   def __init__(self):
      super(BIP32_TESTVECT_4, self).__init__()


   def getChildClass(self, index):
         return BIP32_TESTVECT_5

   def fillKeyPool(self, fsync=True, progressUpdater=emptyFunc):
      indexToUse = CreateChildIndex(1000000000, isHardened=self.HARDCHILD)
      newAkp = self.spawnChild(indexToUse, fsync=fsync, linkToParent=True)
      newAkp.fillKeyPool(fsync=fsync, progressUpdater=progressUpdater)



#############################################################################
class BIP32_TESTVECT_5(ArmoryBip32ExtendedKey):
   FILECODE = 'TESTVEC5'
   TREELEAF  = True
   HARDCHILD = False

   def __init__(self):
      super(BIP32_TESTVECT_5, self).__init__()


