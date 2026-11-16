"""I3/I4/I7: real offline signing and host CLI effects remain authorization-bound."""

import json
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import patch

from demos.owned_host import DemoError, main
from lang.limits import MAX_PROCESS_SECONDS


class TestOwnedHostDemo(unittest.TestCase):
    def test_real_cli_lifecycle(self):
        script = Path(__file__).resolve().parents[1] / 'demos' / 'owned_host.py'
        result = subprocess.run([sys.executable, str(script)], capture_output=True,
                                timeout=MAX_PROCESS_SECONDS * 2)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stderr, b'')
        self.assertEqual(json.loads(result.stdout), {
            'pregrant_denied': True, 'low_grant_effect': True, 'revocation_denied': True,
            'exact_endorsement_effect': True, 'endorsement_replay_denied': True,
            'restart_replay_denied': True, 'temporary_state_removed': True})

    def test_failure_is_nonzero_and_payload_free(self):
        with patch('demos.owned_host.run', side_effect=DemoError()), \
                patch('sys.stderr') as stderr:
            self.assertEqual(main(), 1)
        self.assertEqual(''.join(call.args[0] for call in stderr.write.call_args_list),
                         'Owned host demonstration failed\n')
