import unittest
from unittest import mock
import sys

sys.path.append('../common')
sys.path.append('../repository')

from common import interactive as inputs
from repository.vt import vt_const as vt_globals


class InputsTestCases(unittest.TestCase):

    @mock.patch('builtins.input')
    def test_input_positive_detections(self, mock_input):
        mock_input.side_effect = ['35+', '25-', '15']
        positive_verdicts = inputs.input_string('Positive verdicts', str_format=vt_globals.REGEX_POSITIVES)
        self.assertEqual(positive_verdicts, '35+')
        positive_verdicts = inputs.input_string('Positive verdicts', str_format=vt_globals.REGEX_POSITIVES)
        self.assertEqual(positive_verdicts, '25-')
        positive_verdicts = inputs.input_string('Positive verdicts', str_format=vt_globals.REGEX_POSITIVES)
        self.assertEqual(positive_verdicts, '15')

    @mock.patch('builtins.input')
    def test_input_bytesize(self, mock_input):
        mock_input.side_effect = ['1mb-', '25kb+', '100', '100mb+', '99mb']
        # note: 100 and 100mb+ should fail, and 99mb succeed
        size = inputs.input_string('Size', str_format=vt_globals.REGEX_SIZE)
        self.assertEqual(size, '1mb-')
        size = inputs.input_string('Size', str_format=vt_globals.REGEX_SIZE)
        self.assertEqual(size, '25kb+')
        size = inputs.input_string('Size', str_format=vt_globals.REGEX_SIZE)
        self.assertEqual(size, '99mb')

    @mock.patch('builtins.input')
    def test_input_selection(self, mock_input):
        mock_input.side_effect = [1, 2]
        selection = inputs.input_selection('Select type', choices=vt_globals.FILETYPE_LIST, default='pe',
                                           indent_level=2, render_flat=True)
        self.assertEqual(selection, 'macho')
        selection = inputs.input_selection('Select vendor', choices=vt_globals.REDUCED_VENDOR_LIST,
                                           default='microsoft', indent_level=2, render_flat=True)
        self.assertEqual(selection, 'crowdstrike')


if __name__ == '__main__':
    unittest.main()
