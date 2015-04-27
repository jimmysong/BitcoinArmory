################################################################################
#
# Copyright (C) 2011-2014, Armory Technologies, Inc.                         
# Distributed under the GNU Affero General Public License (AGPL v3)
# See LICENSE or http://www.gnu.org/licenses/agpl.html
#
################################################################################
#
# Project:    Armory
# Author:     Andy Ofiesh
# Website:    www.bitcoinarmory.com
# Orig Date:  2 January, 2014
#
################################################################################
import sys
sys.path.append('..')
from pytest.Tiab import TiabTest
import unittest
import sys
sys.path.append('..')

from armoryengine.Decorators import *

# NOT a real unit test. To verify this test properly
# uncomment the decorator and specify the email arguments
# The email arguments should never be pushed to the repo
# Run the test and check your email
class EmailOutputTest(TiabTest):

   def testEmailOutput(self):
      actualResult = someStringOutputFunction("World!")
      expectedResult = "Hello World!"
      self.assertEqual(actualResult, expectedResult)
      
# @EmailOutput(<Sending Email>, <Sending Email Password>, <List of To Addresses>, <Email Subject>)
def someStringOutputFunction(inputString):
   return "Hello " + inputString


################################################################################
class VerifyArgTypeTest(unittest.TestCase):
   """
   This is a ridiculous test.  The argument-aware decorator has plenty of
   nested functions on its own -- but now we have to make a ton more nested
   functions here in these tests, in order to test them -- especially the
   assertRaise tests which requires we create a function that creates a
   decorated function.
   """

   #############################################################################
   def testSimple(self):

      @VerifyArgTypes(a=int, b=str, c=float)
      def testFunc(a,b,c):
         return b*a + ' ' + str(c)

      
      out = testFunc(2,'-', 3.2)
      self.assertEqual(out, '-- 3.2')

      def failingTest1():
         testFunc(1.1, '-', 3.2)

      def failingTest2():
         testFunc(2, 9, 3.2)
      
      def failingTest3():
         testFunc(2, '-', 'hello')

      def failingTest4():
         testFunc(2, 9, 'hello')

      self.assertRaises(TypeError, failingTest1)
      self.assertRaises(TypeError, failingTest2)
      self.assertRaises(TypeError, failingTest3)
      self.assertRaises(TypeError, failingTest4)


   #############################################################################
   def testSomeArgs(self):

      @VerifyArgTypes(a=int, c=float)
      def testFunc(a,b,c):
         return str(b)*a + ' ' + str(c)

      
      self.assertEqual(testFunc(2,'-', 3.2), '-- 3.2')
      self.assertEqual(testFunc(2, 0, 3.2),  '00 3.2')

      def failingTest1():
         testFunc(1.1, 0, 3.2)

      def failingTest2():
         testFunc(1.1, '-', 3.2)
      
      def failingTest3():
         testFunc(1, 0, '-')

      self.assertRaises(TypeError, failingTest1)
      self.assertRaises(TypeError, failingTest2)
      self.assertRaises(TypeError, failingTest3)

   #############################################################################
   def testArgsNotExist(self):

      def defineFuncWithInvalidDecorator():
         @VerifyArgTypes(a=int, b=str, d=int)
         def testFunc(a,b,c):
            return b*a + str(c)

         # This shouldn't run, it should fail before getting here
         assertTrue(False)


      self.assertRaises(TypeError, defineFuncWithInvalidDecorator)
   

   #############################################################################
   def testWithStarArgs(self):

      @VerifyArgTypes(a=int, c=float)
      def testFunc(a,b,c, *args):
         return a+b+c+len(args)

      self.assertEqual(testFunc(2, 0, 3.2),  5.2)
      self.assertEqual(testFunc(2, 0, 3.2, 99),  6.2)
      self.assertEqual(testFunc(2, 0, 3.2, 99, 99),  7.2)

      def failingTest1():
         testFunc(1.1, 0, 3.2)

      def failingTest2():
         testFunc(1.1, 0, 3.2, 99)

      def failingTest3():
         testFunc(1.1, 0, 3.2, 99, 99)

      self.assertRaises(TypeError, failingTest1)
      self.assertRaises(TypeError, failingTest2)
      self.assertRaises(TypeError, failingTest3)

   #############################################################################
   def testWithStarStar(self):

      @VerifyArgTypes(a=int, c=float)
      def testFunc(a,b,c, **kwargs):
         return a+b+c+len(kwargs)

      self.assertEqual(testFunc(2, 0, 3.2),  5.2)
      self.assertEqual(testFunc(2, 0, 3.2, d=99),  6.2)
      self.assertEqual(testFunc(2, 0, 3.2, d=99, e=99),  7.2)

      def failingTest1():
         testFunc(1.1, 0, 3.2)

      def failingTest2():
         testFunc(1.1, 0, 3.2, d=99)

      def failingTest3():
         testFunc(1.1, 0, 3.2, d=99, e=99)

      self.assertRaises(TypeError, failingTest1)
      self.assertRaises(TypeError, failingTest2)
      self.assertRaises(TypeError, failingTest3)

   #############################################################################
   def testWithStarAndStarStar(self):

      @VerifyArgTypes(a=int, c=float)
      def testFunc(a,b,c, *args, **kwargs):
         return a+b+c+len(kwargs)+len(args)

      self.assertEqual(testFunc(2, 0, 3.2),  5.2)
      self.assertEqual(testFunc(2, 0, 3.2, d=99),  6.2)
      self.assertEqual(testFunc(2, 0, 3.2, d=99, e=99),  7.2)
      self.assertEqual(testFunc(2, 0, 3.2, 99),  6.2)
      self.assertEqual(testFunc(2, 0, 3.2, 99, 99),  7.2)
      self.assertEqual(testFunc(2, 0, 3.2, 99, d=99),  7.2)
      self.assertEqual(testFunc(2, 0, 3.2, 99, 99, d=99, e=99),  9.2)

      def failingTest1():
         testFunc(1.1, 0, 3.2)

      def failingTest2():
         testFunc(1.1, 0, 3.2, d=99)

      def failingTest3():
         testFunc(1.1, 0, 3.2, d=99, e=99)

      def failingTest4():
         testFunc(1.1, 0, 3.2, 99)

      def failingTest5():
         testFunc(1.1, 0, 3.2, 99, 99)

      def failingTest6():
         testFunc(1.1, 0, 3.2, 99, d=99)

      def failingTest7():
         testFunc(1.1, 0, 3.2, 99,99, d=99, e=99)

      self.assertRaises(TypeError, failingTest1)
      self.assertRaises(TypeError, failingTest2)
      self.assertRaises(TypeError, failingTest3)
      self.assertRaises(TypeError, failingTest4)
      self.assertRaises(TypeError, failingTest5)
      self.assertRaises(TypeError, failingTest6)
      self.assertRaises(TypeError, failingTest7)


   #############################################################################
   def testTupleTypes(self):

      @VerifyArgTypes(a=int, c=float, b=(int,str))
      def testFunc(a,b,c, *args, **kwargs):
         return a+int(b)+c+len(kwargs)+len(args)

      self.assertEqual(testFunc(2, 9, 3.2), 14.2)
      self.assertEqual(testFunc(2, '9', 3.2), 14.2)
      self.assertEqual(testFunc(2, '9', 3.2, 'a'), 15.2)
      self.assertEqual(testFunc(2, '9', 3.2, 'a', extra='abc'), 16.2)

      def failingTest1():
         testFunc(2,   1.1, 3.2)

      def failingTest2():
         testFunc(2,   None, 3.2, d=99)

      def failingTest3():
         testFunc(1.1, 0, 3.2, d=99, e=99)

      self.assertRaises(TypeError, failingTest1)
      self.assertRaises(TypeError, failingTest2)
      self.assertRaises(TypeError, failingTest3)


   #############################################################################
   def testListTypes(self):

      # Making sure we can pass a list as well as a tuple (isinstance only 
      # accepts tuples, but VerifyArgTypes will take a list and convert)
      @VerifyArgTypes(a=int, c=float, b=[int,str])
      def testFunc(a,b,c, *args, **kwargs):
         return a+int(b)+c+len(kwargs)+len(args)

      self.assertEqual(testFunc(2, 9, 3.2), 14.2)
      self.assertEqual(testFunc(2, '9', 3.2), 14.2)
      self.assertEqual(testFunc(2, '9', 3.2, 'a'), 15.2)
      self.assertEqual(testFunc(2, '9', 3.2, 'a', extra=5), 16.2)

      def failingTest1():
         testFunc(2,   1.1, 3.2)

      def failingTest2():
         testFunc(2,   None, 3.2, d=99)

      def failingTest3():
         testFunc(1.1, 0, 3.2, d=99, e=99)


      self.assertRaises(TypeError, failingTest1)
      self.assertRaises(TypeError, failingTest2)
      self.assertRaises(TypeError, failingTest3)

   #############################################################################
   def testNoneTypes(self):

      # Making sure we can pass a list as well as a tuple (isinstance only 
      # accepts tuples, but VerifyArgTypes will take a list and convert)
      @VerifyArgTypes(a=[str,int,None], c=[float, int])
      def testFunc(a,b,c):
         return float(a)+int(b)+c if a is not None else int(b)+c

      self.assertEqual(testFunc('2', 9, 3.2), 14.2)
      self.assertEqual(testFunc(2, '9', 3.2), 14.2)
      self.assertEqual(testFunc(None, '9', 3.2), 12.2)

      def failingTest1():
         testFunc(1.1, '2', 3.2)

      def failingTest2():
         testFunc(2, None, 3.2)

      def failingTest3():
         testFunc(2, '9', None)

      self.assertRaises(TypeError, failingTest1)
      self.assertRaises(TypeError, failingTest2)
      self.assertRaises(TypeError, failingTest3)




# Running tests with "python <module name>" will NOT work for any Armory tests
# You must run tests with "python -m unittest <module name>" or run all tests with "python -m unittest discover"
# if __name__ == "__main__":
#    unittest.main()
