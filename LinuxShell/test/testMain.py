from unittest import TestCase
from apps.LinuxShell import main
import os.path

class TestMain(TestCase):
    def setUp(self):
        self.app = main.Main()

    def test_execCommand(self):
        args = {'command': ['echo Hello World']}
        cmdRes = self.app.execCommand(args)
        self.assertEqual(cmdRes, [b'Hello World\n'])

    def test_secureCopy(self):
        dir_path = os.path.dirname(os.path.realpath(__file__))
        localPath = os.path.abspath(os.path.join(dir_path, os.pardir)) + "\scripts\\test.sh"
        remotePath = '/tmp/test.sh'

        args = {'localPath': localPath, 'remotePath': remotePath}
        message = self.app.secureCopy(args)
        self.assertEqual(message, "SUCCESS")

    def test_runLocalScriptRemotely(self):
        dir_path = os.path.dirname(os.path.realpath(__file__))
        localPath = os.path.abspath(os.path.join(dir_path, os.pardir)) + "\scripts\\test.sh"

        args = {'localPath': localPath}
        cmdRes = self.app.runLocalScriptRemotely(args)
        self.assertEqual(cmdRes, [b'Hello World\n'])

    def test_shutdown(self):
        self.assertIsNone(self.app.shutdown())
