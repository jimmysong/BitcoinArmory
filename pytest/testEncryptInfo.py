################################################################################
#
# Copyright (C) 2011-2014, Armory Technologies, Inc.                         
# Distributed under the GNU Affero General Public License (AGPL v3)
# See LICENSE or http://www.gnu.org/licenses/agpl.html
#
################################################################################
#
# Project:    Armory
# Author:     Alan Reiner
# Website:    www.bitcoinarmory.com
# Orig Date:  20 September, 2014
#
################################################################################
import sys
sys.path.append('..')
import unittest
import sys
sys.path.append('..')
import textwrap

from armoryengine.ArmoryUtils import *
from armoryengine.ArmoryEncryption import *

# Here's some variables that are recurring through the tests, that have been
# extracted from code known to be working. 
SampleKdfAlgo   = 'ROMIXOV2'
SampleKdfMem    = 4194304
SampleKdfIter   = 3
SampleKdfSalt   = SecureBinaryData(hex_to_binary( \
      '38c1355eb2b39330bab691b58b7ee0c0c7fbc6c706c088244d3fd3becea5e958'))
SamplePasswd    = SecureBinaryData('TestPassword')
SampleKdfOutKey = SecureBinaryData(hex_to_binary( \
      'affc2dbe749a9f5b3c01b4a88fb150fcdb7b10187555e9009265eec911108e8b'))
SampleKdfID     = hex_to_binary('92c130cd7399b061')
SamplePlainStr  = SecureBinaryData('test_encrypt____')  
SampleCryptAlgo = 'AE256CBC'
SampleCryptIV8  = 'randomIV'
SampleCryptIV16 = stretchIV(SecureBinaryData(SampleCryptIV8), 16)
SampleCryptStr  = SecureBinaryData(hex_to_binary( \
      '467450aeb63bbe83d9758cb4ae44477e'))
SampleMasterEKey = SecureBinaryData('samplemasterkey0' + '\xfa'*16)
SampleMasterCrypt = SecureBinaryData(hex_to_binary( \
      '5ab2e112def50f0e1f4fd7e5d81a3af37c6754f28bc7533c2db9f779ba0a79b8'))
SampleMasterEkeyID = hex_to_binary('0524acc0d96da57f')

LOGERROR('LOGGING IS ENABLED:  APPROX 20 ERROR MESSAGES IS NORMAL')
LOGERROR('If the tests pass ("OK" is at the end), you can ignore the errors')


def skipFlagExists():
   if os.path.exists('skipmosttests.flag'):
      print '*'*80
      print 'SKIPPING MOST TESTS.  REMOVE skipMostTests.flag TO REENABLE'
      print '*'*80
      return True
   else:
      return False



# NOT a real unit test. To verify this test properly
# uncomment the decorator and specify the email arguments
# The email arguments should never be pushed to the repo
# Run the test and check your email
class ArmoryCryptInfoTest(unittest.TestCase):

   def setUp(self):
      pass
      
   def tearDown(self):
      pass

   def assertNoRaise(self, func, *args, **kwargs):
      try:
         func(*args, **kwargs)
      except Exception as e:
         self.fail("Assert raised in assertNoRaise:" + str(e))
         

   #############################################################################
   @unittest.skipIf(skipFlagExists(),'')
   def testStretchIV(self):
      ivShort = SecureBinaryData(hex_to_binary('00112233445566'))
      iv8     = SecureBinaryData(hex_to_binary('0011223344556677'))
      ivLong  = SecureBinaryData(hex_to_binary('001122334455667788'))

      shaIV8  = SecureBinaryData(hex_to_binary( \
         '0379fb77234a85af1a48b2011fe9e5ff6f7c6cc41b6844ddcbb7cfe877fef52c'
         '38ab0e8ed5883567027286602815441c9b47f75a73810ea529588d7890d45ad0'))

      shaIV7  = SecureBinaryData(hex_to_binary( \
         '076395aedf1aeab1e1f00866038fb00b3baea1dbade91c4ef6315bd429811f9a'
         'a6e3966682c2a90ebe11a110418680b0005439fe9f2c0220a993a14528b84c56'))

      self.assertRaises(BadInputError, stretchIV, iv8, 65)
      self.assertRaises(BadInputError, stretchIV, iv8, 0)
      self.assertRaises(TypeError, stretchIV, iv8.toBinStr(), 16)
      self.assertNoRaise(stretchIV, iv8, 1)
      self.assertNoRaise(stretchIV, iv8, 8)
      self.assertNoRaise(stretchIV, iv8, 16)

      # Identity tests
      self.assertEqual(stretchIV(iv8,     8), iv8    )
      self.assertEqual(stretchIV(ivShort, 7), ivShort)
      self.assertEqual(stretchIV(ivLong , 9), ivLong )

      # Truncation tests
      self.assertEqual(stretchIV(ivLong,  8), iv8    )
      self.assertEqual(stretchIV(ivLong,  3).toBinStr(), iv8.toBinStr()[:3])
      
      # Stretch tests
      self.assertEqual(stretchIV(iv8,      9).toBinStr(),  shaIV8.toBinStr()[:9])
      self.assertEqual(stretchIV(iv8,     16).toBinStr(),  shaIV8.toBinStr()[:16])
      self.assertEqual(stretchIV(ivShort,  8).toBinStr(),  shaIV7.toBinStr()[:8])
      self.assertEqual(stretchIV(ivShort, 16).toBinStr(),  shaIV7.toBinStr()[:16])


   #############################################################################
   @unittest.skipIf(skipFlagExists(),'')
   def testEkeyID(self):
      keySBD = SecureBinaryData(hex_to_binary('0011223344556677'))
      keyStr = keySBD.toBinStr()
      hmacIV8 = hex_to_binary(\
         'bf6117ac43c76ed02ab9358e0bbbd9f560be499a471c89e799f4ff2c5e56c13f'
         '9b9561496015321b88866debedc3b10875b2537af97d1374bf0fea5b1079f1a6')

      self.assertTrue(calcEKeyID(keySBD), hmacIV8[:8])
      self.assertTrue(calcEKeyID(keyStr), hmacIV8[:8])
      
      

   #############################################################################
   @unittest.skipIf(skipFlagExists(),'')
   def testACI_construct(self):
      aci = ArmoryCryptInfo()
      self.assertEqual(aci.kdfObjID, NULLKDF)
      self.assertEqual(aci.encryptAlgo, NULLCRYPT)
      self.assertEqual(aci.keySource, NULLSTR(8))
      self.assertEqual(aci.ivSource, NULLSTR(8))

      self.assertNoRaise(ArmoryCryptInfo, encrAlgo="AE256CFB")
      self.assertNoRaise(ArmoryCryptInfo, encrAlgo="AE256CBC")
      self.assertNoRaise(ArmoryCryptInfo, encrAlgo="IDENTITY")
      self.assertRaises(UnrecognizedCrypto, ArmoryCryptInfo, encrAlgo="UNK")


   #############################################################################
   @unittest.skipIf(skipFlagExists(),'')
   def testACI_boolmethods(self):
      aci = ArmoryCryptInfo()
      self.assertTrue(aci.noEncryption())
      self.assertFalse(aci.useEncryption())
      self.assertFalse(aci.useKeyDerivFunc())
      self.assertFalse(aci.hasStoredIV())
      self.assertRaises(KeyDataError, aci.getEncryptKeySrc)
      ser = aci.serialize()
      self.assertEqual( aci.serialize(),  ArmoryCryptInfo.unserialize(ser).serialize())

      aci = ArmoryCryptInfo(NULLKDF,'AE256CBC','fakkeyid','anything')
      self.assertFalse(aci.noEncryption())
      self.assertTrue(aci.useEncryption())
      self.assertFalse(aci.useKeyDerivFunc())
      self.assertTrue(aci.hasStoredIV())
      self.assertEqual(aci.getEncryptKeySrc(), (CRYPT_KEY_SRC.EKEY_OBJ, 'fakkeyid'))
      ser = aci.serialize()
      self.assertEqual( aci.serialize(),  ArmoryCryptInfo.unserialize(ser).serialize())

      aci = ArmoryCryptInfo(NULLKDF,'AE256CBC','fakkeyid','PUBKEY20')
      self.assertFalse(aci.noEncryption())
      self.assertTrue(aci.useEncryption())
      self.assertFalse(aci.useKeyDerivFunc())
      self.assertFalse(aci.hasStoredIV())
      self.assertEqual(aci.getEncryptKeySrc(), (CRYPT_KEY_SRC.EKEY_OBJ, 'fakkeyid'))
      ser = aci.serialize()
      self.assertEqual( aci.serialize(),  ArmoryCryptInfo.unserialize(ser).serialize())
      
      aci = ArmoryCryptInfo('fakkdfid','AE256CBC','PASSWORD','anything')
      self.assertFalse(aci.noEncryption())
      self.assertTrue(aci.useEncryption())
      self.assertTrue(aci.useKeyDerivFunc())
      self.assertTrue(aci.hasStoredIV())
      self.assertEqual(aci.getEncryptKeySrc(), (CRYPT_KEY_SRC.PASSWORD, ''))
      ser = aci.serialize()
      self.assertEqual( aci.serialize(),  ArmoryCryptInfo.unserialize(ser).serialize())

      aci = ArmoryCryptInfo('fakkdfid','AE256CBC','PARCHAIN','PUBKEY20')
      self.assertFalse(aci.noEncryption())
      self.assertTrue(aci.useEncryption())
      self.assertTrue(aci.useKeyDerivFunc())
      self.assertFalse(aci.hasStoredIV())
      self.assertEqual(aci.getEncryptKeySrc(), (CRYPT_KEY_SRC.PARCHAIN, ''))
      ser = aci.serialize()
      self.assertEqual( aci.serialize(),  ArmoryCryptInfo.unserialize(ser).serialize())


   #############################################################################
   @unittest.skipIf(skipFlagExists(),'')
   def testACI_endecrypt_ident(self):
      aci = ArmoryCryptInfo('IDENTITY', 'IDENTITY')
      self.assertFalse(aci.useEncryption())

      result = aci.encrypt(SampleCryptStr)
      self.assertEqual(result, SampleCryptStr)
      
   
   #############################################################################
   @unittest.skipIf(skipFlagExists(), '')
   def testACI_endecrypt_rawkey(self):
      aci = ArmoryCryptInfo(NULLKDF, SampleCryptAlgo, 'RAWKEY32', SampleCryptIV8)
      self.assertTrue(aci.hasStoredIV())

      rawKey32 = SecureBinaryData('\x3a'*32)

      result = aci.encrypt(SamplePlainStr, rawKey32)
      decrypted = aci.decrypt(result, rawKey32)
      self.assertEqual(decrypted, SamplePlainStr)
      
      rawKey33_bad = SecureBinaryData('\x3a'*33)
      self.assertRaises(EncryptionError, aci.encrypt, SamplePlainStr, rawKey33_bad)
      self.assertRaises(InitVectError, aci.encrypt, SamplePlainStr, rawKey32, 
                                                ivData=SecureBinaryData('aaa'))

      plain_bad = SecureBinaryData('test_encrypt___')  # not padded
      self.assertRaises(EncryptionError, aci.encrypt, plain_bad, rawKey32)

      plain_bad = SecureBinaryData('test_encrypt_____')  # not padded
      self.assertRaises(EncryptionError, aci.encrypt, plain_bad, rawKey32)
      self.assertEqual(aci.tempKeyDecrypt.getSize(), 0)


      # Try it with something longer than one blocksize
      origPlain = SecureBinaryData('test_encrypt___test_encrypt_____test_encrypt____')  
      result = aci.encrypt(origPlain, rawKey32)
      decrypted = aci.decrypt(result, rawKey32)
      self.assertEqual(decrypted, origPlain)


   #############################################################################
   @unittest.skipIf(skipFlagExists(),'')
   def testACI_endecrypt_password(self):
      kdf = KdfObject(SampleKdfAlgo, memReqd=SampleKdfMem, 
                                     numIter=SampleKdfIter, 
                                     salt=SampleKdfSalt)
      kdfID = hex_to_binary('92c130cd7399b061')

      aci = ArmoryCryptInfo(kdfID, SampleCryptAlgo, 'PASSWORD', SampleCryptIV8)
      self.assertTrue(aci.hasStoredIV())


      # This key we know should come out of the KDF for its params and pwd
      self.assertEqual(kdf.execKDF(SamplePasswd), SampleKdfOutKey)

      # The output of the following two lines are now at the top of the file
      # iv16 = stretchIV(SecureBinaryData(SampleCryptIV8), 16)
      # SampleCryptStr = CryptoAES().EncryptCBC(SamplePlainStr, SampleKdfOutKey, iv16)
      computedEncrypted = aci.encrypt(SamplePlainStr, SamplePasswd, kdfObj=kdf)
      self.assertEqual(SampleCryptStr, computedEncrypted)

      decrypted = aci.decrypt(computedEncrypted, SamplePasswd, kdfObj=kdf)
      self.assertEqual(decrypted, SamplePlainStr)


      # Try it passing in a kdf map
      kdfmap = {kdf.getKdfID(): kdf}
      computedEncrypted = aci.encrypt(SamplePlainStr, SamplePasswd, kdfObj=kdfmap)
      decrypted = aci.decrypt(computedEncrypted, SamplePasswd, kdfObj=kdfmap)
      self.assertEqual(decrypted, SamplePlainStr)
      self.assertEqual(decrypted.getSize(), 16)

      # Try it with something longer than one blocksize
      origPlain = SecureBinaryData('test_encrypt___test_encrypt_____test_encrypt____')  
      result = aci.encrypt(origPlain, SamplePasswd, kdfObj=kdf)
      decrypted = aci.decrypt(result, SamplePasswd, kdfObj=kdf)
      self.assertEqual(decrypted, origPlain)
      self.assertEqual(decrypted.getSize(), 48)



      # Now some things that shoudl cause us to fail
      self.assertRaises(InitVectError, aci.encrypt, origPlain, SamplePasswd, 
                                                ivData=SecureBinaryData('aaa'))

      # Pass it a map that doesn't have the kdf in it
      self.assertRaises(KdfError, aci.encrypt, origPlain, SamplePasswd, kdfObj={})

      # Repeat the not-properly-padded tests 
      plain_bad = SecureBinaryData('test_encrypt___')  # not padded
      self.assertRaises(EncryptionError, aci.encrypt, plain_bad, SamplePasswd)
      plain_bad = SecureBinaryData('test_encrypt_____')  # not padded
      self.assertRaises(EncryptionError, aci.encrypt, plain_bad, SamplePasswd)
      self.assertEqual(aci.tempKeyDecrypt.getSize(), 0)


   #############################################################################
   @unittest.skipIf(skipFlagExists(),'')
   def testACI_endecrypt_passwd_supplyIV(self):
      kdf = KdfObject(SampleKdfAlgo, memReqd=SampleKdfMem, 
                                     numIter=SampleKdfIter, 
                                     salt=SampleKdfSalt)
      kdfID = hex_to_binary('92c130cd7399b061')
      self.assertEqual(kdfID, kdf.getKdfID())

      supplyIV = SecureBinaryData(SampleCryptIV8)
      iv16 = stretchIV(supplyIV, 16)

      # Here we exclude the IV 
      aci = ArmoryCryptInfo(kdfID, SampleCryptAlgo, 'PASSWORD')
      self.assertFalse(aci.hasStoredIV())

      # This key we know should come out of the KDF for its params and pwd
      self.assertEqual(kdf.execKDF(SamplePasswd), SampleKdfOutKey)

      computedEncrypted = aci.encrypt(SamplePlainStr, SamplePasswd, iv16, kdfObj=kdf)
      self.assertEqual(SampleCryptStr, computedEncrypted)

      decrypted = aci.decrypt(computedEncrypted, SamplePasswd, iv16, kdfObj=kdf)
      self.assertEqual(decrypted, SamplePlainStr)






################################################################################
################################################################################
class ArmoryKDFTests(unittest.TestCase):

   def setUp(self):
      pass
      
   def tearDown(self):
      pass

   def assertNoRaise(self, func, *args, **kwargs):
      try:
         func(*args, **kwargs)
      except Exception as e:
         self.fail("Assert raised in assertNoRaise:" + str(e))
         

   #############################################################################
   @unittest.skipIf(skipFlagExists(),'')
   def testConstructKDF(self):
      mem   = 64*KILOBYTE
      niter = 2
      salt  = hex_to_binary('5c'*16)

      self.assertNoRaise(KdfObject)
      self.assertNoRaise(KdfObject, 'IDENTITY')
      self.assertRaises(BadInputError, KdfObject, SampleKdfAlgo)
      self.assertNoRaise(KdfObject, SampleKdfAlgo, memReqd=mem, numIter=niter, salt=salt)


   #############################################################################
   @unittest.skipIf(skipFlagExists(),'')
   def testKDFSerUnserRT(self):
      mem   = 64*KILOBYTE
      niter = 2
      salt  = hex_to_binary('5c'*16)
      kdf = KdfObject(SampleKdfAlgo, memReqd=mem, numIter=niter, salt=salt)
      expectedID = hex_to_binary('a69c7bf79583f155')

      bp = BinaryPacker()
      bp.put(BINARY_CHUNK, SampleKdfAlgo)
      bp.put(BINARY_CHUNK, 'sha512__')
      bp.put(UINT32,       int(64*KILOBYTE))
      bp.put(UINT32,       2)
      bp.put(VAR_STR,      '\x5c'*16)
      expectedSerialize = bp.getBinaryString()
      self.assertEqual(kdf.serialize(), expectedSerialize)
      self.assertEqual(kdf.getKdfID(), expectedID)
      
      kdf = KdfObject().unserialize(expectedSerialize)
      self.assertEqual(kdf.serialize(), expectedSerialize)
      

   #############################################################################
   @unittest.skipIf(skipFlagExists(),'')
   def testRunKDF(self):
      # These KDF params were taken directly from a testnet wallet in 0.92
      

      kdf = KdfObject(SampleKdfAlgo, memReqd=SampleKdfMem, 
                                     numIter=SampleKdfIter, 
                                     salt=SampleKdfSalt)
      actualOut = kdf.execKDF(SamplePasswd)
      self.assertEqual(actualOut, SampleKdfOutKey)


   #############################################################################
   @unittest.skipIf(skipFlagExists(),'')
   def testCreateNewKDF(self):
      timeTgt = 0.5
      memTgt  = 64*KILOBYTE

      self.assertNoRaise(KdfObject.CreateNewKDF, 'IDENTITY')
      self.assertRaises(KeyError, KdfObject.CreateNewKDF, SampleKdfAlgo)
      self.assertRaises(KdfError, KdfObject.CreateNewKDF, SampleKdfAlgo, targSec=0.1, maxMem=16384)

      newkdf = KdfObject.CreateNewKDF(SampleKdfAlgo, targSec=timeTgt, maxMem=memTgt)



      start = RightNow()
      newkdf.execKDF(SecureBinaryData('TestPassword'))
      timeTaken = RightNow() - start

      if not (timeTgt/3 < timeTaken < 1.5*timeTgt):
         print '%s:  KDF computational-target test failed' % self.id()
         print textwrap.dedent("""
            THIS TEST SHOUILD BE DISABLED IF THE TESTING ENV IS NOT CONSISTENT
            The computational test may execute under different loads than the final
            execution.  We expect compute time to between T/2 and T, and we explicitly 
            check for between T/3 and 1.5*T to accommodate small inconsistencies.
            This is expected to always pass, but it is feasible that conditions are
            not such that we can expect this to pass consistently.""")
         print 'Time Target: %0.2f' % timeTgt
         print 'Actual Time: %0.2f' % timeTaken
         self.fail('KDF computational-target test failed')
         

      if not (newkdf.memReqd == memTgt):
         print '%s:  KDF computational-target test failed' % self.id()
         print textwrap.dedent("""
            THIS TEST SHOULD BE DISABLED IF TESTING ENV IS EXCEPTIONALLY SLOW
            We have chosen a low max memory for the time target (%0.2f sec) so   
            that it's likely the KDF will hit that limit and be required to 
            increase numIter instead.  If this test is run on an exceptionally 
            slow machine (RPi?), this might not be the case.  In that case, 
            this test should be disabled.""" % timeTgt)
         print 'Mem Expected: %d' % int(memTgt)
         print 'Actual Mem:   %d' % int(newkdf.memReqd)
         self.assertTrue( newkdf.getMemoryReqtBytes() == memTgt)


################################################################################
################################################################################
class ArmoryEncryptKeyTests(unittest.TestCase):

   def setUp(self):
      # Use the KDF from KDF tests.  We already know its ID, pwd output, etc.
      self.kdf = KdfObject(SampleKdfAlgo, memReqd=SampleKdfMem, 
                                          numIter=SampleKdfIter, 
                                          salt=SampleKdfSalt)


   def tearDown(self):
      pass

   def assertNoRaise(self, func, *args, **kwargs):
      try:
         func(*args, **kwargs)
      except Exception as e:
         self.fail('Assert raised in assertNoRaise: "' + str(e) + '"')


   #############################################################################
   @unittest.skipIf(skipFlagExists(),'')
   def testEkeyConstruct_Default(self):
      self.assertNoRaise(EncryptionKey)
         
      ekey = EncryptionKey()
      self.assertEqual(ekey.ekeyID,          NULLSTR())
      self.assertEqual(ekey.masterKeyCrypt,  NULLSBD())
      self.assertEqual(ekey.masterKeyPlain,  NULLSBD())
      self.assertEqual(ekey.testStringEncr,  NULLSTR(0))
      self.assertEqual(ekey.testStringPlain, NULLSTR(0))
      self.assertEqual(ekey.keyTripleHash,   NULLSTR(0))
      self.assertEqual(ekey.relockAtTime,    0)
      self.assertEqual(ekey.lockTimeout,     10)

      self.assertTrue(ekey.keyCryptInfo.noEncryption())

      self.assertRaises(EncryptionError, ekey.getEncryptionKeyID)
      self.assertRaises(KeyDataError, ekey.getPlainEncryptionKey)
   

   #############################################################################
   @unittest.skipIf(skipFlagExists(),'')
   def testEkeyCreate(self):
      ekey = EncryptionKey()
      self.assertRaises(UnrecognizedCrypto, 
                    ekey.createNewMasterKey, self.kdf, 'UNK', SamplePasswd)

      ekey.createNewMasterKey(self.kdf, SampleCryptAlgo, SamplePasswd,
                           preGenKey=SampleMasterEKey, preGenIV8=SampleCryptIV8)
      self.assertEqual(ekey.masterKeyCrypt, SampleMasterCrypt)

      # Same as above but with SBD IV
      ekey.createNewMasterKey(self.kdf, SampleCryptAlgo, SamplePasswd,
                           preGenKey=SampleMasterEKey, 
                           preGenIV8=SecureBinaryData(SampleCryptIV8))
      self.assertEqual(ekey.masterKeyCrypt, SampleMasterCrypt)
      
      # Try passing key data not the right size
      self.assertRaises(KeyDataError, ekey.createNewMasterKey, 
                           self.kdf, SampleCryptAlgo, SamplePasswd, 
                           preGenKey=SamplePlainStr, preGenIV8=SampleCryptIV8)
      
      # Try passing IV data not the right size
      self.assertRaises(InitVectError, ekey.createNewMasterKey, 
                          self.kdf, SampleCryptAlgo, SamplePasswd, 
                          preGenKey=SampleMasterEKey, preGenIV8=SampleCryptIV8*2)
      
      ser = ekey.serialize()
      self.assertEqual(ser, ekey.unserialize(ser).serialize())
      self.assertEqual(ekey.masterKeyCrypt, SampleMasterCrypt)
      self.assertEqual(ekey.getEncryptionKeyID(), SampleMasterEkeyID)


   #############################################################################
   @unittest.skipIf(skipFlagExists(),'')
   def testEkeyUnlockRelock(self):
      ekey = EncryptionKey()
      ekey.createNewMasterKey(self.kdf, SampleCryptAlgo, SamplePasswd,
                           preGenKey=SampleMasterEKey, preGenIV8=SampleCryptIV8)

      self.assertEqual(ekey.masterKeyCrypt, SampleMasterCrypt)

      self.assertTrue(ekey.unlock(SamplePasswd, justVerify=True))
      self.assertFalse(ekey.unlock(SecureBinaryData('Badpwd'), justVerify=True))

      ekey.unlock(SamplePasswd)
      self.assertEqual(ekey.masterKeyPlain, SampleMasterEKey)
      self.assertEqual(ekey.getPlainEncryptionKey(), SampleMasterEKey)
      self.assertEqual(ekey.masterKeyCrypt, SampleMasterCrypt)
      ekey.lock(SamplePasswd)
      self.assertEqual(ekey.masterKeyPlain.getSize(), 0)


   #############################################################################
   @unittest.skipIf(skipFlagExists(),'')
   def testEkeySerUnserRT(self):
      ekey = EncryptionKey()
      ekey.createNewMasterKey(self.kdf, SampleCryptAlgo, SamplePasswd,
                           preGenKey=SampleMasterEKey, preGenIV8=SampleCryptIV8)

      # Manually construct the expected serialization of the Ekey
      bp = BinaryPacker()
      aci = ArmoryCryptInfo(SampleKdfID, SampleCryptAlgo, 'PASSWORD', SampleCryptIV8)
      bp.put(BINARY_CHUNK, SampleMasterEkeyID)
      bp.put(VAR_STR,      SampleMasterCrypt.toBinStr())
      bp.put(BINARY_CHUNK, aci.serialize())
      bp.put(VAR_STR,      '')
      bp.put(VAR_STR,      '')
      bp.put(VAR_STR,      '')
      expectedSer = bp.getBinaryString()

      self.assertTrue(ekey.isLocked())

      serEkey = ekey.serialize()
      self.assertEqual(serEkey, expectedSer)
      self.assertEqual(ekey.unserialize(serEkey).serialize(), serEkey)
      self.assertTrue(ekey.isLocked())

      # ekey was just unserialzied, which means the kdf obj refs are gone
      # (They are set in createNewMasterKey, but lost when ser-unser)
      self.assertRaises(KdfError, ekey.unlock, SamplePasswd)
      ekey.unlock(SamplePasswd, self.kdf)
      self.assertEqual(ekey.masterKeyPlain, SampleMasterEKey)
      self.assertEqual(ekey.getPlainEncryptionKey(), SampleMasterEKey)
      self.assertEqual(ekey.masterKeyCrypt, SampleMasterCrypt)
      self.assertFalse(ekey.isLocked())

      ekey.lock()
      self.assertTrue(ekey.isLocked())
      self.assertEqual(ekey.masterKeyPlain, NULLSBD())
      self.assertEqual(ekey.masterKeyCrypt, SampleMasterCrypt)
      self.assertRaises(KeyDataError, ekey.getPlainEncryptionKey)

      ekey.setKdfObjectRef(self.kdf)
      ekey.unlock(SamplePasswd)
      self.assertFalse(ekey.isLocked())
      self.assertEqual(ekey.masterKeyPlain, SampleMasterEKey)
      self.assertEqual(ekey.masterKeyCrypt, SampleMasterCrypt)

      ekey.lock()
      self.assertTrue(ekey.isLocked())
      self.assertEqual(ekey.masterKeyPlain, NULLSBD())
      self.assertEqual(ekey.masterKeyCrypt, SampleMasterCrypt)
      

   #############################################################################
   @unittest.skipIf(skipFlagExists(),'')
   def testEkeyTimeout(self):
      ekey = EncryptionKey()
      ekey.createNewMasterKey(self.kdf, SampleCryptAlgo, SamplePasswd,
                           preGenKey=SampleMasterEKey, preGenIV8=SampleCryptIV8)


      self.assertEqual(ekey.lockTimeout, 10)
      ekey.setLockTimeout(0.5)
      self.assertEqual(ekey.lockTimeout, 3)
      ekey.setLockTimeout(4)
      self.assertEqual(ekey.lockTimeout, 4)
      ekey.setLockTimeout(2)
      self.assertEqual(ekey.lockTimeout, 3)

      ekey.unlock(SamplePasswd)
      self.assertFalse(ekey.isLocked())
      ekey.checkLockTimeout()
      self.assertFalse(ekey.isLocked())
      time.sleep(3.5)
      ekey.checkLockTimeout()
      self.assertTrue(ekey.isLocked())



   #############################################################################
   @unittest.skipIf(skipFlagExists(),'')
   def testEkeyChangePwd(self):
      oldPwd = SamplePasswd
      badPwd = SecureBinaryData('BadPassword')
      newPwd = SecureBinaryData('NewPassword')
      oldAlgo = SampleCryptAlgo
      newAlgo = 'AE256CFB'

      oldKdf = self.kdf
      newKdf = KdfObject.CreateNewKDF(SampleKdfAlgo, targSec=0.1, maxMem=32*KILOBYTE)


      # This function will create one ekey from the old params, and one ekey 
      # from the new params/arguments.  It will the attempt to the change the
      # old one to the new one, and compare output with the one created directly
      def testChangeEncryptParams(changeToKdf, changeToAlgo, changeToPwd):
         # Override "None" values with old* values for created the cmp ekey
         cmpKdf  = oldKdf  if changeToKdf  is None else changeToKdf
         cmpAlgo = oldAlgo if changeToAlgo is None else changeToAlgo
         cmpPwd  = oldPwd  if changeToPwd  is None else changeToPwd 

         ekeyCmp = EncryptionKey()
         ekeyCmp.createNewMasterKey(cmpKdf, cmpAlgo, cmpPwd,
                           preGenKey=SampleMasterEKey, preGenIV8=SampleCryptIV8)

         # This is the key we're going to modify
         ekey = EncryptionKey()
         ekey.createNewMasterKey(oldKdf, oldAlgo, oldPwd,
                              preGenKey=SampleMasterEKey, preGenIV8=SampleCryptIV8)
         
         ekey.changeEncryptionParams(oldPwd, 
                                     changeToPwd, 
                                     newKdf=changeToKdf,
                                     newEncryptAlgo=changeToAlgo,
                                     useSameIV=True)
         
         self.assertEqual(ekey.ekeyID,          ekeyCmp.ekeyID)
         self.assertEqual(ekey.masterKeyCrypt,  ekeyCmp.masterKeyCrypt)
         self.assertEqual(ekey.keyCryptInfo.serialize(), ekeyCmp.keyCryptInfo.serialize())
         self.assertTrue(ekey.isLocked())

         ekey.unlock(cmpPwd)
         ekeyCmp.unlock(cmpPwd)

         self.assertFalse(ekey.isLocked())
         self.assertFalse(ekeyCmp.isLocked())
         self.assertEqual(ekey.masterKeyPlain,  ekeyCmp.masterKeyPlain)


      # For these tests, "None" means don't change it.  However, to be sure
      # that all code paths work, we will also try every combination including
      # passing the old values in as if they were new, which should generate
      # the same result


      # Test changing different combinations of params
      testChangeEncryptParams(None,   None,    newPwd)
      testChangeEncryptParams(newKdf, None,    None  )
      testChangeEncryptParams(None,   newAlgo, None  )
      testChangeEncryptParams(newKdf, newAlgo, newPwd)

      if not skipFlagExists():
         # Test changing two at a time
         testChangeEncryptParams(newKdf, None,    newPwd)
         testChangeEncryptParams(newKdf, newAlgo, None  )
         testChangeEncryptParams(None,   newAlgo, newPwd)
         # All the above tests sometimes replacing "None" with old* vals
         testChangeEncryptParams(oldKdf, None,    newPwd)
         testChangeEncryptParams(None,   oldAlgo, newPwd)
         testChangeEncryptParams(oldKdf, oldAlgo, newPwd)
         testChangeEncryptParams(newKdf, None,    oldPwd)
         testChangeEncryptParams(newKdf, oldAlgo, None  )
         testChangeEncryptParams(newKdf, oldAlgo, oldPwd)
         testChangeEncryptParams(None,   newAlgo, oldPwd)
         testChangeEncryptParams(newKdf, newAlgo, None  )
         testChangeEncryptParams(newKdf, newAlgo, oldPwd)
         testChangeEncryptParams(newKdf, oldAlgo, newPwd)
         testChangeEncryptParams(newKdf, newAlgo, oldPwd)
         testChangeEncryptParams(oldKdf, newAlgo, newPwd)

      
      # Finally, a few raises
      ekey = EncryptionKey()
      ekey.createNewMasterKey(oldKdf, oldAlgo, oldPwd)
      self.assertRaises(PassphraseError, ekey.changeEncryptionParams, badPwd, newPwd)
      self.assertRaises(EncryptionError, ekey.changeEncryptionParams, oldPwd)
      self.assertRaises(EncryptionError, ekey.changeEncryptionParams, oldPwd, oldPwd)
      self.assertRaises(UnrecognizedCrypto, ekey.changeEncryptionParams, 
                                             oldPwd, newPwd, newEncryptAlgo="UNK")



################################################################################
################################################################################
class ArmoryMultiPwdKeyTests(unittest.TestCase):

   def setUp(self):
      # Setup for up to N=4, though our tests may use less
      self.kdfSalts = ['\xaa'*16, '\xbb'*16, '\xcc'*16]
      self.labels   = ['JoePassword', u'PwdAlice', u'DoItRight\u2122']
      self.passwds  = ['p455w04d', u'foreignpwd', u'unicodepwd\u2122']
      self.passwds  = [SecureBinaryData(toBytes(p)) for p in self.passwds]
      self.passwds2 = [[MPEK_FRAG_TYPE.PASSWORD, p] for p in self.passwds]
      self.kdfs = []
      self.kdfIDs = []

      # Create 3 KDFs
      for i in range(3):
         self.kdfs.append( KdfObject(SampleKdfAlgo, 
                                     memReqd=SampleKdfMem, 
                                     numIter=SampleKdfIter, 
                                     salt=self.kdfSalts[i]) )
         self.kdfIDs.append(self.kdfs[-1].getKdfID())

      # Manually compute what the three plaintext frags will be
      self.pfrags = []
      self.pfrags2 = []
      for i in range(3):
         xypairs = SplitSecret(SampleMasterEKey.toBinStr(), 2,3, 32)
         self.pfrags = [SecureBinaryData(pair[1]) for pair in xypairs]
         self.pfrags2 = [[MPEK_FRAG_TYPE.PLAINFRAG, pf.copy()] for pf in self.pfrags]

      for i in range(3):
         self.fragKeys = [self.kdfs[i].execKDF(self.passwds[i]) for i in range(3)]
         self.fragKeys2 = [[MPEK_FRAG_TYPE.FRAGKEY, fk.copy()] for fk in self.fragKeys]


   def tearDown(self):
      pass

   def assertNoRaise(self, func, *args, **kwargs):
      try:
         func(*args, **kwargs)
      except Exception as e:
         self.fail('Assert raised in assertNoRaise: "' + str(e) + '"')


   #############################################################################
   @unittest.skipIf(skipFlagExists(),'')
   def testMkeyConstruct_Default(self):
      self.assertNoRaise(MultiPwdEncryptionKey)
         
      mkey = MultiPwdEncryptionKey()
      self.assertEqual(mkey.ekeyID,          NULLSTR())
      self.assertEqual(mkey.masterKeyPlain,  NULLSBD())
      self.assertEqual(len(mkey.einfos),     0)
      self.assertEqual(len(mkey.efrags),     0)
      self.assertEqual(len(mkey.labels),     0)
      self.assertEqual(mkey.relockAtTime,    0)
      self.assertEqual(mkey.lockTimeout,     10)

      self.assertRaises(EncryptionError, mkey.getEncryptionKeyID)
   

   #############################################################################
   @unittest.skipIf(skipFlagExists(),'')
   def testMkeyCreate(self):
      M,N = 2,3
      mkey = MultiPwdEncryptionKey()
      mkey.createNewMasterKey(self.kdfs, SampleCryptAlgo, 
                                M, self.passwds, self.labels,
                                preGenKey=SampleMasterEKey)


      ser = mkey.serialize()
      self.assertEqual(ser, mkey.unserialize(ser).serialize())
      self.assertEqual(mkey.getEncryptionKeyID(), SampleMasterEkeyID)

      # Try passing key data not the right size
      self.assertRaises(KeyDataError, mkey.createNewMasterKey, 
                           self.kdfs, SampleCryptAlgo, 
                           M, self.passwds, self.labels,
                           preGenKey=SamplePlainStr)
      
      self.passwds[1] = NULLSBD()
      self.assertRaises(BadInputError, mkey.createNewMasterKey, 
                           self.kdfs, SampleCryptAlgo, 
                           M, self.passwds, self.labels,
                           preGenKey=SamplePlainStr)
      


   #############################################################################
   @unittest.skipIf(skipFlagExists(),'')
   def testMkeyUnlockRelock_Passwords(self):
      M,N = 2,3
      mkey = MultiPwdEncryptionKey()
      mkey.createNewMasterKey(self.kdfs, SampleCryptAlgo, 
                                M, self.passwds, self.labels,
                                preGenKey=SampleMasterEKey)


      NULLPASSWD = [MPEK_FRAG_TYPE.NONE, NULLSBD()]

      goodLists = []
      goodLists.append([NULLPASSWD,       self.passwds2[1], self.passwds2[2]])
      goodLists.append([self.passwds2[0], NULLPASSWD,       self.passwds2[2]])
      goodLists.append([self.passwds2[0], self.passwds2[1], NULLPASSWD,     ])
      goodLists.append([self.passwds2[0], self.passwds2[1], self.passwds2[2]])

      badLists = []
      badLists.append([NULLPASSWD,       NULLPASSWD,       NULLPASSWD,    ])
      badLists.append([NULLPASSWD,       self.passwds2[1], NULLPASSWD,    ])
      badLists.append([self.passwds2[0], self.passwds2[1]])  # short list, good pwds
      ###########

      for gl in goodLists:
         self.assertTrue(mkey.masterKeyPlain.getSize() == 0)
         self.assertTrue(mkey.unlock(gl))
         self.assertTrue(mkey.masterKeyPlain.getSize() > 0)
         self.assertEqual(mkey.masterKeyPlain, SampleMasterEKey)
         self.assertTrue(mkey.lock())
         self.assertTrue(mkey.isLocked())
         self.assertTrue(mkey.masterKeyPlain.getSize() == 0)

      for bl in badLists:
         self.assertTrue(mkey.masterKeyPlain.getSize() == 0)
         self.assertRaises(PassphraseError, mkey.unlock, bl)
         self.assertTrue(mkey.isLocked())
         self.assertTrue(mkey.masterKeyPlain.getSize() == 0)
         

      pwdpair = lambda s: [MPEK_FRAG_TYPE.PASSWORD, SecureBinaryData(s)]
      badPwdList = [pwdpair('abc'), pwdpair('123'), NULLPASSWD]
      self.assertFalse(mkey.verifyPassphrase(badPwdList))
      self.assertTrue(mkey.verifyPassphrase(goodLists[0]))


   #############################################################################
   @unittest.skipIf(skipFlagExists(),'')
   def testMkeyUnlockRelock_PwdFrags(self):
      M,N = 2,3
      mkey = MultiPwdEncryptionKey()
      mkey.createNewMasterKey(self.kdfs, SampleCryptAlgo, 
                                M, self.passwds, self.labels,
                                preGenKey=SampleMasterEKey)


      NULLPASSWD = [MPEK_FRAG_TYPE.NONE, NULLSBD()]

      goodLists = []
      goodLists.append([NULLPASSWD,       self.passwds2[1], self.pfrags2[2]])
      goodLists.append([self.pfrags2[0],  NULLPASSWD,       self.passwds2[2]])
      goodLists.append([self.pfrags2[0],  self.pfrags2[1],  NULLPASSWD,     ])
      goodLists.append([self.passwds2[0], self.pfrags2[1],  self.pfrags2[2]])
      goodLists.append([self.pfrags2[0],  self.pfrags2[1],  self.pfrags2[2]])

      badLists = []
      badLists.append([NULLPASSWD,       NULLPASSWD,       NULLPASSWD,    ])
      badLists.append([NULLPASSWD,       self.pfrags2[1],  NULLPASSWD,    ])
      badLists.append([self.pfrags2[0],  self.pfrags2[1]])  # short list, good pwds
      ###########

      for gl in goodLists:
         self.assertTrue(mkey.masterKeyPlain.getSize() == 0)
         self.assertTrue(mkey.unlock(gl))
         self.assertTrue(mkey.masterKeyPlain.getSize() > 0)
         self.assertEqual(mkey.masterKeyPlain, SampleMasterEKey)
         self.assertTrue(mkey.lock())
         self.assertTrue(mkey.isLocked())
         self.assertTrue(mkey.masterKeyPlain.getSize() == 0)

      for bl in badLists:
         self.assertTrue(mkey.masterKeyPlain.getSize() == 0)
         self.assertRaises(PassphraseError, mkey.unlock, bl)
         self.assertTrue(mkey.isLocked())
         self.assertTrue(mkey.masterKeyPlain.getSize() == 0)
         

      pwdpair = lambda s: [MPEK_FRAG_TYPE.PLAINFRAG, SecureBinaryData(s)]
      badPwdList = [pwdpair('\x03'*32), pwdpair('\x83'*32), NULLPASSWD]
      self.assertFalse(mkey.verifyPassphrase(badPwdList))
      self.assertTrue(mkey.verifyPassphrase(goodLists[0]))


   #############################################################################
   def testMkeyUnlockRelock_FragKeys(self):
      M,N = 2,3
      mkey = MultiPwdEncryptionKey()
      mkey.createNewMasterKey(self.kdfs, SampleCryptAlgo, 
                                M, self.passwds, self.labels,
                                preGenKey=SampleMasterEKey)


      NULLPASSWD = [MPEK_FRAG_TYPE.NONE, NULLSBD()]

      goodLists = []
      goodLists.append([NULLPASSWD,        self.passwds2[1],  self.pfrags2[2] ])
      goodLists.append([self.pfrags2[0],   NULLPASSWD,        self.passwds2[2]])
      goodLists.append([self.pfrags2[0],   self.pfrags2[1],   NULLPASSWD,     ])
      goodLists.append([self.passwds2[0],  self.pfrags2[1],   self.pfrags2[2] ])
      goodLists.append([self.pfrags2[0],   self.pfrags2[1],   self.pfrags2[2] ])

      fkeys = [None]*3
      for i in range(3):
         fkeys[i] = [MPEK_FRAG_TYPE.FRAGKEY, mkey.getFragEncryptionKey(i, self.passwds2)]
         self.assertEqual(fkeys[i][1], self.fragKeys[i])

      # Test the values that come directly out of the getFragEncryptionKey func
      goodLists.append([NULLPASSWD,        fkeys[1],          fkeys[2]        ])
      goodLists.append([fkeys[0],          NULLPASSWD,        self.passwds2[2]])
      goodLists.append([fkeys[0],          self.pfrags2[1],   NULLPASSWD,     ])
      goodLists.append([self.passwds2[0],  self.pfrags2[1],   fkeys[2]        ])
      goodLists.append([self.pfrags2[0],   fkeys[1],          self.pfrags2[2] ])


      badLists = []
      badLists.append([NULLPASSWD,         NULLPASSWD,        NULLPASSWD,     ])
      badLists.append([NULLPASSWD,         fkeys[1],          NULLPASSWD,     ])
      badLists.append([self.pfrags2[0],    fkeys[1]])  # short list, good pwds
      badLists.append([fkeys[0],           fkeys[1]])  # short list, good pwds
      ###########

      # Quick test the getPlainFrags matches what we expect:
      computedPFrags = mkey.getPlainFragList(goodLists[1])
      for i in range(len(computedPFrags)):
         self.assertEqual(computedPFrags[i], self.pfrags[i])

      for i,gl in enumerate(goodLists):
         self.assertTrue(mkey.masterKeyPlain.getSize() == 0)
         self.assertTrue(mkey.unlock(gl))
         self.assertTrue(mkey.masterKeyPlain.getSize() > 0)
         self.assertEqual(mkey.masterKeyPlain, SampleMasterEKey)
         self.assertTrue(mkey.lock())
         self.assertTrue(mkey.isLocked())
         self.assertTrue(mkey.masterKeyPlain.getSize() == 0)

      for bl in badLists:
         self.assertTrue(mkey.masterKeyPlain.getSize() == 0)
         self.assertRaises(PassphraseError, mkey.unlock, bl)
         self.assertTrue(mkey.isLocked())
         self.assertTrue(mkey.masterKeyPlain.getSize() == 0)
         

      pwdpair = lambda s: [MPEK_FRAG_TYPE.PLAINFRAG, SecureBinaryData(s)]
      badPwdList = [pwdpair('\x03'*32), pwdpair('\x83'*32), NULLPASSWD]
      self.assertFalse(mkey.verifyPassphrase(badPwdList))
      self.assertTrue(mkey.verifyPassphrase(goodLists[0]))

   #############################################################################
   @unittest.skipIf(skipFlagExists(),'')
   def testMkeySerUnserRT(self):
      M,N = 2,3
      mkey = MultiPwdEncryptionKey()
      mkey.createNewMasterKey(self.kdfs, SampleCryptAlgo, 
                                M, self.passwds, self.labels,
                                preGenKey=SampleMasterEKey)

      # Manually construct the expected serialization of the mkey
      bp = BinaryPacker()
      aci = ArmoryCryptInfo(SampleKdfID, SampleCryptAlgo, 'PASSWORD', SampleCryptIV8)
      bp.put(BINARY_CHUNK, SampleMasterEkeyID)
      bp.put(BINARY_CHUNK, mkey.mkeyID)
      bp.put(UINT8,        2)
      bp.put(UINT8,        3)
      for i in range(3):
         iv = mkey.einfos[i].ivSource
         aci = ArmoryCryptInfo(self.kdfIDs[i], SampleCryptAlgo, 'PASSWORD', iv)
         bp.put(BINARY_CHUNK,  aci.serialize())
         bp.put(VAR_STR,  mkey.efrags[i].toBinStr())
         bp.put(VAR_UNICODE,  self.labels[i])
      expectedSer = bp.getBinaryString()

      self.assertTrue(mkey.isLocked())

      serEkey = mkey.serialize()
      self.assertEqual(serEkey, expectedSer)
      self.assertEqual(mkey.unserialize(serEkey).serialize(), serEkey)
      self.assertTrue(mkey.isLocked())

      self.assertRaises(KdfError, mkey.unlock, self.passwds2)
      mkey.unlock(self.passwds2, kdfObjList=self.kdfs)
      self.assertEqual(mkey.masterKeyPlain, SampleMasterEKey)
      self.assertFalse(mkey.isLocked())

      mkey.lock()
      self.assertTrue(mkey.isLocked())
      self.assertEqual(mkey.masterKeyPlain, NULLSBD())

      mkey.setKdfObjectRefList(self.kdfs)
      mkey.unlock(self.passwds2)
      self.assertFalse(mkey.isLocked())
      self.assertEqual(mkey.masterKeyPlain, SampleMasterEKey)

      mkey.lock()
      self.assertTrue(mkey.isLocked())
      self.assertEqual(mkey.masterKeyPlain, NULLSBD())
      


   #############################################################################
   @unittest.skipIf(skipFlagExists(),'')
   def testMkeyChangeSomePasswords(self):
      """
      This is actually quite different from the regular ekey tests.  We don't
      test changing any encryption or KDF params, but do have to try lots of 
      subsets of passwords.  Of interest are both:
         (1) What keys are provided to unlock the key to change pwds
         (2) What pwds are being changed (changing pwds not used for unlocking)
      There's a lot of unique combinations, but with 2-of-3 
      """

      M,N = 2,3
      oldPwds  = self.passwds
      oldPwds2 = self.passwds2
      newPwds  = [SecureBinaryData(a) for a in ['newpwd1','newpwd2','newpwd3']]
      newPwds2 = [[MPEK_FRAG_TYPE.PASSWORD, p.copy()] for p in newPwds]

      oldLbls = self.labels
      newLbls = ['newlblA', u'newlblB\u2122', 'newlblC']

      forceIV8s = ['\xaa'*8, '\xbb'*8, '\xcc'*8]

      def testChangeSomePwds(oldPwdsForUnlock, newPwdsToChange, newLabels=None):
         # First merge the old password list and new passwords
         # finalPwdList is the complete list of N passwords of the final obj
         # changeNewPwds is the partial pwd list for changeSomePasswords()
         # (use NULLSBD for pwd slots that aren't changing)
         finalPwdList  = []
         finalPwdList2 = []
         changeNewPwds = []
         for i in range(3):
            if i in newPwdsToChange:
               finalPwdList.append(newPwds[i])
               finalPwdList2.append(newPwds2[i])
               changeNewPwds.append(newPwds[i])
            else:
               finalPwdList.append(oldPwds[i])
               finalPwdList2.append(oldPwds2[i])
               changeNewPwds.append(NULLSBD())

         # Part of our tests involve unlocking with different subsets of pwds
         unlockPwds2 = []
         for i in range(3):
            if i in oldPwdsForUnlock:
               unlockPwds2.append(oldPwds2[i])
            else:
               unlockPwds2.append([MPEK_FRAG_TYPE.NONE, NULLSBD()])


         if newLabels is None:
            newLabels = oldLbls

         # Create a multi-pwd key that is already in the final state
         mkeyCmp = MultiPwdEncryptionKey()
         mkeyCmp.createNewMasterKey(self.kdfs, SampleCryptAlgo, M, finalPwdList, 
                                    newLabels, preGenKey=SampleMasterEKey, 
                                    preGenIV8List=forceIV8s)

         # Create a multi-pwd with all old passwords, will change it as test
         mkey = MultiPwdEncryptionKey()
         mkey.createNewMasterKey(self.kdfs, SampleCryptAlgo, M, oldPwds, oldLbls,
                           preGenKey=SampleMasterEKey, preGenIV8List=forceIV8s)
         

   
         mkey.changeSomePasswords(unlockPwds2, 
                                  changeNewPwds, 
                                  kdfList=self.kdfs,
                                  newLabels=newLabels)
                                  
         
         self.assertEqual(mkey.ekeyID,          mkeyCmp.ekeyID)
         for i in range(3):
            self.assertEqual(mkey.einfos[i].serialize(),  mkeyCmp.einfos[i].serialize())
            self.assertEqual(mkey.efrags[i],  mkeyCmp.efrags[i])

         self.assertTrue(mkey.isLocked())

         NULLPASSWD = [MPEK_FRAG_TYPE.NONE, NULLSBD()]
         newunlock2 = [finalPwdList2[0], finalPwdList2[1], NULLPASSWD]
         mkey.unlock(newunlock2)
         mkeyCmp.unlock(newunlock2)
         self.assertFalse(mkey.isLocked())
         self.assertFalse(mkeyCmp.isLocked())
         self.assertEqual(mkey.masterKeyPlain,  mkeyCmp.masterKeyPlain)
         self.assertEqual(mkey.masterKeyPlain,  SampleMasterEKey)

         mkey.lock()
         mkeyCmp.lock()
         self.assertTrue(mkey.isLocked())
         self.assertTrue(mkeyCmp.isLocked())

         newunlock2 = [finalPwdList2[0], NULLPASSWD, finalPwdList2[2]]
         self.assertTrue(mkey.verifyPassphrase(newunlock2))

         newunlock2 = [NULLPASSWD, finalPwdList2[1], finalPwdList2[2]]
         self.assertTrue(mkey.verifyPassphrase(newunlock2))

         newunlock2 = [finalPwdList2[0], finalPwdList2[1], finalPwdList2[2]]
         self.assertTrue(mkey.verifyPassphrase(newunlock2))
         
         for i in range(3):
            self.assertEqual(mkey.labels[i], newLabels[i])

         serMkey = mkey.serialize()
         mkey2 = MultiPwdEncryptionKey().unserialize(serMkey)
         self.assertEqual(serMkey, mkey2.serialize())


      # Test changing some passwords.  The first two args are just lists of ints
      # Change all passwords
      testChangeSomePwds([0,1,2], [0,1,2])
      testChangeSomePwds([0,1,2], [0,1,2], newLbls)
      testChangeSomePwds([0,1],   [0,1,2])
      testChangeSomePwds([0,2],   [0,1,2])
      testChangeSomePwds([1,2],   [0,1,2])

      # Change only some passwords
      testChangeSomePwds([0,1,2], [0])
      testChangeSomePwds([0,1,2], [1])
      testChangeSomePwds([0,1,2], [2])
      testChangeSomePwds([0,1,2], [0,1])
      testChangeSomePwds([0,1,2], [0,2])
      testChangeSomePwds([0,1,2], [1,2])
      testChangeSomePwds([0,1],   [0,1,2])
      testChangeSomePwds([0,2],   [0,1,2])
      testChangeSomePwds([1,2],   [0,1,2])

      testChangeSomePwds([0,1],   [0])
      testChangeSomePwds([0,1],   [1])
      testChangeSomePwds([0,1],   [2])  # change a pwd that wasn't entered!

      testChangeSomePwds([0,1],   [2], newLbls)  # change a pwd that wasn't entered!

   #############################################################################
   @unittest.skipIf(skipFlagExists(),'')
   def testMkeyChangeEncryptionMofN(self):
      """
      These tests don't have to be as rigorous, because the test will actually
      look a lot like the code itself:  mkey will overwrite itself with a new
      fragmentation of the master key
      """
      oldM,oldN = 2,3
      newM,newN = 3,5

      oldPwds  = self.passwds
      oldPwds2 = self.passwds2

      newPwds  = [SecureBinaryData(int_to_hex(i+10000)) for i in range(newN)]
      newPwds2 = [[MPEK_FRAG_TYPE.PASSWORD, p.copy()] for p in newPwds]

      newLbls = ['NewLabel%d'%i for i in range(newN)]

      newAlgo = 'AE256CFB'
      newKdfs = []
      newKdfIDs = []
      for i in range(newN):
         newKdfs.append( KdfObject(SampleKdfAlgo, 
                                   memReqd=SampleKdfMem, 
                                   numIter=SampleKdfIter, 
                                   salt=int_to_binary(i, widthBytes=1)*16))
         newKdfIDs.append(self.kdfs[-1].getKdfID())

      mkey = MultiPwdEncryptionKey()
      mkey.createNewMasterKey(self.kdfs, SampleCryptAlgo, oldM, self.passwds, 
                              self.labels, preGenKey=SampleMasterEKey)

      oldEkeyID = mkey.ekeyID
         

   
      NULLPASSWD = [MPEK_FRAG_TYPE.NONE, NULLSBD()]
      mkey.changeMultiEncryption(self.kdfs,
                                 [oldPwds2[0], NULLPASSWD, oldPwds2[2]],
                                 newKdfs, 
                                 newAlgo,
                                 newM,
                                 newPwds,
                                 newLbls)
                              
      
      
      self.assertEqual(mkey.M, newM)
      self.assertEqual(mkey.N, newN)
      self.assertEqual(mkey.ekeyID, oldEkeyID)
      for i in range(newN):
         self.assertEqual(mkey.labels[i], newLbls[i])


      self.assertTrue(mkey.verifyPassphrase([ newPwds2[0],
                                              newPwds2[1],
                                              newPwds2[2],
                                              newPwds2[3],
                                              newPwds2[4] ]))
                                  
      self.assertTrue(mkey.verifyPassphrase([ newPwds2[0],
                                              NULLPASSWD,
                                              newPwds2[2],
                                              newPwds2[3],
                                              newPwds2[4] ]))

      self.assertTrue(mkey.verifyPassphrase([ NULLPASSWD,
                                              NULLPASSWD,
                                              newPwds2[2],
                                              newPwds2[3],
                                              newPwds2[4] ]))

      self.assertRaises(PassphraseError, mkey.verifyPassphrase, 
                                                [ NULLPASSWD,
                                                  NULLPASSWD,
                                                  newPwds2[2],
                                                  newPwds2[3],
                                                  NULLPASSWD  ])


      mkey.unlock([NULLPASSWD, NULLPASSWD, newPwds2[2], newPwds2[3], newPwds2[4]])
      self.assertEqual(mkey.masterKeyPlain, SampleMasterEKey)




################################################################################
################################################################################
class ArmoryChainedACITests(unittest.TestCase):

   def setUp(self):
      # Use the KDF from KDF tests.  We already know its ID, pwd output, etc.
      self.kdf = KdfObject(SampleKdfAlgo, memReqd=SampleKdfMem, 
                                          numIter=SampleKdfIter, 
                                          salt=SampleKdfSalt)

      self.ekey = EncryptionKey()
      self.ekey.createNewMasterKey(self.kdf, SampleCryptAlgo, SamplePasswd,
                           preGenKey=SampleMasterEKey, preGenIV8=SampleCryptIV8)
      self.ekeyID = self.ekey.ekeyID

      # For multi-pwd key encryption
      self.M,self.N = 2,3
      self.kdfList  = []
      self.pwdList  = []
      self.lblList  = []
      for i in range(self.N):
         self.kdfList.append(KdfObject('ROMIXOV2', memReqd=32768, numIter=1, salt='\x32'*16))
         self.pwdList.append(SecureBinaryData('password%d'%i))
         self.lblList.append(u'NewLabel%d'%i)

      self.mkey = MultiPwdEncryptionKey()
      self.mkey.createNewMasterKey(self.kdfList, 'AE256CBC', self.M, 
                                   self.pwdList, self.lblList, 
                                   preGenKey=SampleMasterEKey)
      self.mkeyID = self.mkey.ekeyID

      xypairs = SplitSecret(SampleMasterEKey.toBinStr(), 2,3, 32)
      pfrags  = [SecureBinaryData(pair[1]) for pair in xypairs]

      self.unlockPwd = []
      NULLPASSWD = [MPEK_FRAG_TYPE.NONE, NULLSBD()]
      self.unlockPwd.append([ [MPEK_FRAG_TYPE.PASSWORD,  self.pwdList[0]],
                              [MPEK_FRAG_TYPE.NONE,      NULLSBD()      ],
                              [MPEK_FRAG_TYPE.PASSWORD,  self.pwdList[2]] ])

      self.unlockPwd.append([ [MPEK_FRAG_TYPE.PASSWORD,  self.pwdList[0]],
                              [MPEK_FRAG_TYPE.PASSWORD,  self.pwdList[1]], 
                              [MPEK_FRAG_TYPE.PASSWORD,  self.pwdList[2]] ])

      self.unlockPwd.append([ [MPEK_FRAG_TYPE.PASSWORD,  self.pwdList[0]],
                              [MPEK_FRAG_TYPE.NONE,      self.pwdList[1]], 
                              [MPEK_FRAG_TYPE.PLAINFRAG, pfrags[2]      ] ])


   def tearDown(self):
      pass

   def assertNoRaise(self, func, *args, **kwargs):
      try:
         func(*args, **kwargs)
      except Exception as e:
         self.fail('Assert raised in assertNoRaise: "' + str(e) + '"')


   #############################################################################
   @unittest.skipIf(skipFlagExists(),'')
   def testACI_chained_endecrypt(self):

      # Manual/direct encryption with master key
      expectCrypt = CryptoAES().EncryptCBC(SamplePlainStr, SampleMasterEKey, SampleCryptIV16)

      # Now attempt the same encryption using chained ACI
      aci = ArmoryCryptInfo(NULLKDF, SampleCryptAlgo, self.ekeyID, SampleCryptIV8)
      self.assertTrue(self.ekey.isLocked())
      computeCrypt = aci.encrypt(SamplePlainStr, SamplePasswd, kdfObj=self.kdf, ekeyObj=self.ekey)
      self.assertTrue(self.ekey.isLocked())
      self.assertEqual(computeCrypt, expectCrypt)
      
      # Check that it works with maps
      kdfmap = {self.kdf.getKdfID(): self.kdf}
      ekeymap= {self.ekey.ekeyID: self.ekey}
      self.assertTrue(self.ekey.isLocked())
      computeCrypt = aci.encrypt(SamplePlainStr, SamplePasswd, kdfObj=kdfmap, ekeyObj=ekeymap)
      self.assertTrue(self.ekey.isLocked())
      self.assertEqual(computeCrypt, expectCrypt)

      # Test that decryption works the same way
      self.assertTrue(self.ekey.isLocked())
      plainAgain = aci.decrypt(computeCrypt, SamplePasswd, kdfObj=kdfmap, ekeyObj=ekeymap)
      self.assertTrue(self.ekey.isLocked())
      self.assertEqual(plainAgain, SamplePlainStr)


      # Try using a KDF with a master encryption key (error)
      aci = ArmoryCryptInfo(self.kdf, SampleCryptAlgo, self.ekeyID, SampleCryptIV8)
      self.assertRaises(EncryptionError, aci.encrypt, SamplePlainStr, SamplePasswd, 
                                                   kdfObj=self.kdf, ekeyObj=self.ekey)

      # Try using a non-matching ekey ID (error)
      aci = ArmoryCryptInfo(NULLKDF, SampleCryptAlgo, 'FAKEEKID', SampleCryptIV8)
      self.assertRaises(EncryptionError, aci.encrypt, SamplePlainStr, SamplePasswd, 
                                                   kdfObj=self.kdf, ekeyObj=self.ekey)

      # Try not passing in a password (ekey is locked) (error)
      aci = ArmoryCryptInfo(NULLKDF, SampleCryptAlgo, self.ekeyID, SampleCryptIV8)
      self.assertTrue(self.ekey.isLocked())
      self.assertRaises(EncryptionError, aci.encrypt, SamplePlainStr, 
                                                   kdfObj=self.kdf, ekeyObj=self.ekey)
      self.assertTrue(self.ekey.isLocked())
      
      # Test unlocking the ekey first, then not passing in any unlock params
      self.ekey.unlock(SamplePasswd)
      self.assertFalse(self.ekey.isLocked())
      computeCrypt = aci.encrypt(SamplePlainStr, ekeyObj=self.ekey)
      self.assertFalse(self.ekey.isLocked()) # should stay unlocked 
      self.assertEqual(computeCrypt, expectCrypt)
      self.ekey.lock(SamplePasswd)
      self.assertTrue(self.ekey.isLocked())
      
      # Now we confirm again that it's locked and if fails without a pwd
      aci = ArmoryCryptInfo(NULLKDF, SampleCryptAlgo, self.ekeyID, SampleCryptIV8)
      self.assertRaises(EncryptionError, aci.encrypt, SamplePlainStr, 
                                                   kdfObj=self.kdf, ekeyObj=self.ekey)

      # Now try to unlock without supplying a kdfObj -- this should work 
      # because we supplied the kdf object to the ekey when we created it,
      # so it should have it in its kdfRef member.  
      self.assertTrue(self.ekey.isLocked()) 
      computeCrypt = aci.encrypt(SamplePlainStr, SamplePasswd, ekeyObj=self.ekey)
      self.assertTrue(self.ekey.isLocked()) 
      self.assertEqual(computeCrypt, expectCrypt)

      # Now we create a new, identical ekey but without a valid kdfRef
      newEkey = EncryptionKey().unserialize(self.ekey.serialize())
      self.assertTrue(newEkey.isLocked()) 
      computeCrypt = aci.encrypt(SamplePlainStr, SamplePasswd, kdfObj=self.kdf, ekeyObj=newEkey)
      self.assertTrue(newEkey.isLocked()) 
      self.assertEqual(computeCrypt, expectCrypt)

      # Now we should throw an error when we omit the kdf object
      self.assertRaises(KdfError, aci.encrypt, SamplePlainStr, SamplePasswd, ekeyObj=newEkey)



   #############################################################################
   def testACI_chained_endecrypt_multipwd(self):

      # Manual/direct encryption with master key
      expectCrypt = CryptoAES().EncryptCBC(SamplePlainStr, SampleMasterEKey, SampleCryptIV16)

      # Now attempt the same encryption using chained ACI
      aci = ArmoryCryptInfo(NULLKDF, SampleCryptAlgo, self.mkeyID, SampleCryptIV8)
      self.assertTrue(self.mkey.isLocked())
      computeCrypt = aci.encrypt(SamplePlainStr, self.unlockPwd[0], kdfObj=self.kdfList, ekeyObj=self.mkey)
      self.assertTrue(self.mkey.isLocked())
      self.assertEqual(computeCrypt, expectCrypt)
      
      # Check that it works with the 
      kdfmap = {}
      for kdf in self.kdfList:
         kdfmap[kdf.getKdfID()] = kdf

      mkeymap= {self.mkeyID: self.mkey}
      self.assertTrue(self.mkey.isLocked())
      computeCrypt = aci.encrypt(SamplePlainStr, self.unlockPwd[0], kdfObj=kdfmap, ekeyObj=mkeymap)
      self.assertTrue(self.mkey.isLocked())
      self.assertEqual(computeCrypt, expectCrypt)

      # Test that decryption works the same way
      self.assertTrue(self.mkey.isLocked())
      plainAgain = aci.decrypt(computeCrypt, self.unlockPwd[0], kdfObj=kdfmap, ekeyObj=mkeymap)
      self.assertTrue(self.mkey.isLocked())
      self.assertEqual(plainAgain, SamplePlainStr)


      # Try using a KDF with a master encryption key (error)
      aci = ArmoryCryptInfo(self.kdf, SampleCryptAlgo, self.ekeyID, SampleCryptIV8)
      self.assertRaises(EncryptionError, aci.encrypt, SamplePlainStr, self.unlockPwd[0], 
                                                   kdfObj=self.kdf, ekeyObj=self.mkey)

      # Try using a non-matching mkey ID (error)
      aci = ArmoryCryptInfo(NULLKDF, SampleCryptAlgo, 'FAKEEKID', SampleCryptIV8)
      self.assertRaises(EncryptionError, aci.encrypt, SamplePlainStr, self.unlockPwd[0], 
                                                   kdfObj=self.kdf, ekeyObj=self.mkey)


      # Try not passing in a password (mkey is locked) (error)
      aci = ArmoryCryptInfo(NULLKDF, SampleCryptAlgo, self.ekeyID, SampleCryptIV8)
      self.assertTrue(self.mkey.isLocked())
      self.assertRaises(EncryptionError, aci.encrypt, SamplePlainStr, 
                                                   kdfObj=self.kdf, ekeyObj=self.mkey)
      self.assertTrue(self.mkey.isLocked())
      
      # Test unlocking the mkey first, then not passing in any unlock params
      self.mkey.unlock(self.unlockPwd[0])
      self.assertFalse(self.mkey.isLocked())
      computeCrypt = aci.encrypt(SamplePlainStr, ekeyObj=self.mkey)
      self.assertFalse(self.mkey.isLocked()) # should stay unlocked 
      self.assertEqual(computeCrypt, expectCrypt)
      self.mkey.lock()
      self.assertTrue(self.mkey.isLocked())
      
      # Now we confirm again that it's locked and if fails without a pwd
      aci = ArmoryCryptInfo(NULLKDF, SampleCryptAlgo, self.ekeyID, SampleCryptIV8)
      self.assertRaises(EncryptionError, aci.encrypt, SamplePlainStr, 
                                                   kdfObj=self.kdf, ekeyObj=self.mkey)

      # Now try to unlock without supplying a kdfObj -- this should work 
      # because we supplied the kdf object to the mkey when we created it,
      # so it should have it in its kdfRef member.  
      self.assertTrue(self.mkey.isLocked()) 
      computeCrypt = aci.encrypt(SamplePlainStr, self.unlockPwd[0], ekeyObj=self.mkey)
      self.assertTrue(self.mkey.isLocked()) 
      self.assertEqual(computeCrypt, expectCrypt)

      # Now we create a new, identical mkey but without a valid kdfRef
      newMkey = MultiPwdEncryptionKey().unserialize(self.mkey.serialize())
      self.assertTrue(newMkey.isLocked()) 
      computeCrypt = aci.encrypt(SamplePlainStr, self.unlockPwd[0], kdfObj=self.kdfList, ekeyObj=newMkey)
      self.assertTrue(newMkey.isLocked()) 
      self.assertEqual(computeCrypt, expectCrypt)

      # Now we should throw an error when we omit the kdf object
      self.assertRaises(KdfError, aci.encrypt, SamplePlainStr, self.unlockPwd[0], ekeyObj=newMkey)




if __name__ == "__main__":
   unittest.main()








