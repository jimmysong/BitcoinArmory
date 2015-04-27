import sys
import unittest

from PyQt4.QtGui import QApplication
from PyQt4.QtTest import QTest

sys.path.append('..')
from pytest.Tiab import TiabTest
from ArmoryQt import ArmoryMainWindow


class MainWindowTest(TiabTest):

    def setUp(self):
        self.app = ArmoryMainWindow()

    def testButtons(self):
        self.assertEqual(self.app,"")
