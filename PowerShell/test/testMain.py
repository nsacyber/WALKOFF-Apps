from unittest import TestCase
from apps.PowerShell import main
import os.path


class TestMain(TestCase):
    def setUp(self):
        self.app = main.Main()

    def test_execCommand(self):
        args = {'command': ['Powershell -Command Write-Host Hello World']}
        cmdRes = self.app.execCommand(args)
        self.assertEqual(cmdRes, [b'Hello World\n'])

    def test_runLocalScriptRemotely(self):
        dir_path = os.path.dirname(os.path.realpath(__file__))
        localPath = os.path.abspath(os.path.join(dir_path, os.pardir)) + "\scripts\\test.ps1"

        args = {'localPath': localPath}
        cmdRes = self.app.runLocalScriptRemotely(args)
        self.assertEqual(cmdRes, [b'Hello World\n'])

    def test_shutdown(self):
        self.assertIsNone(self.app.shutdown())

