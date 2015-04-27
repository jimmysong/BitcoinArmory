from ArmoryUtils import *
from ArmoryWallet import *

#####
def SplitChildIndex(cIdx): 
   if not cIdx < 1<<32:
      raise ValueError('Child indices must be less than 2^32')
   childNum   = int(cIdx & 0x7fffffff)
   isHardened = (cIdx & 0x80000000) > 0
   return [childNum, isHardened]

#####
def CreateChildIndex(childNum, isHardened): 
   if not childNum < 1<<31:
      raise ValueError('Child number must be less than 2^31')

   topBit = 0x80000000 if isHardened else 0
   return childNum | topBit   

################################################################################
class Bip32TreeNode(object):

   def __init__(self):

   #############################################################################
   def getChildClass(self, index):
      # This method is used not only to get the child TreeNode class,
      # but to define limits on which children nodes should be avail
      raise NotImplementedError




################################################################################
class MultisigTreeNode(Bip32TreeNode):
   def __init__(self, M=None, N=None):
      self.M = None
      self.N = None
      self.siblings = []  # siblings of the multisig

   #############################################################################
   def getScript(self):
      pklist = [tn.akpObject.getSerializedPubKey() for tn in self.siblings]
      rawMsScript= pubkeylist_to_multisig_script(pklist, self.M)
      p2shScript = script_to_p2sh_script(rawMsScript)

   #############################################################################
   def getScrAddr(self):
      if self.scrAddrStr is None:
         self.scrAddrStr = script_to_scrAddr(p2shScript)
      return self.scrAddrStr


################################################################################
class Bip44RootTreeNode(Bip32TreeNode):
   def getChildClass(self, index):
      idx,hard = SplitChildIndex(index)
      if index==44 and hard:
         return Bip44PurposeTreeNode
      else:
         raise NotImplementedError("No TreeNodes other than 44' (0x2c') allowed!")


   def isLeaf(self):
      return False


################################################################################
class StdBip32RootTreeNode(Bip32TreeNode):
   def getChildClass(self, index):
      idx,hard = SplitChildIndex(index)
      if hard:
         return StdBip32WalletTreeNode
      else:
         raise NotImplementedError("Must use hardened derivation!")


   def isLeaf(self):
      return False


################################################################################
class Bip44PurposeTreeNode(Bip32TreeNode):
   def getChildClass(self, index):
      idx,hard = SplitChildIndex(index)
      expectedIdx = 1 if USE_TESTNET else 0
      if index==expectedIdx and hard:
         return Bip44BitcoinTreeNode
      else:
         raise NotImplementedError("No TreeNodes other than %d' (0x%s)' allowed" % \
                                                      idx, int_to_hex(idx))

   def isLeaf(self):
      return False



################################################################################
class Bip44BitcoinTreeNode(Bip32TreeNode):
   def getChildClass(self, index):
      idx,hard = SplitChildIndex(index)
      if hard:
         return StdBip32WalletTreeNode
      else:
         raise NotImplementedError("Must use hardened derivation!")


   def isLeaf(self):
      return False



################################################################################
class StdBip32WalletTreeNode(Bip32TreeNode):
   def getChildClass(self, index):
      idx,hard = SplitChildIndex(index)
      if hard:
         raise NotImplementedError("Must use non-hardened derivation!")
      elif idx%2==0:
         return StdBip32ExternalChainTreeNode
      else:
         return StdBip32InternalChainTreeNode
         

   def isLeaf(self):
      return False

################################################################################
class StdBip32ExternalChainTreeNode(Bip32TreeNode):
   def getChildClass(self, index):
      return StdBip32LeafTreeNode
         
   def isLeaf(self):
      return False


################################################################################
class StdBip32InternalChainTreeNode(Bip32TreeNode):
   def getChildClass(self, index):
      return StdBip32LeafTreeNode
         
   def isLeaf(self):
      return False


################################################################################
class StdBip32LeafTreeNode(Bip32TreeNode):

   def getChildClass(self, index):
      return None

   def isLeaf(self):
      return True



