import unittest

import SecProj

class TestInputMethods(unittest.TestCase):
    @mock.patch('sanitized.input', create=True)
    def test_sanitized_yn(self, mocked_input):
        mocked_input.side_effect = ['y','testtest','n','test','test','test','1','test','test test, in test city','test@testc.com','y','testtest','test','n']
