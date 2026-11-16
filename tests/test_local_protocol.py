"""I6/I7: hostile JSON and blocked peers stay bounded and fail closed."""
import os
import threading
import time
import unittest

from gate.local_protocol import JsonLines, ProtocolError, decode_object, encode_object
from lang.limits import MAX_ARG_DEPTH, MAX_ARG_NODES, MAX_LINE_BYTES, MAX_PROCESS_SECONDS


class TestLocalProtocol(unittest.TestCase):
    def test_strict_json_and_unicode(self):
        good = {'text': 'snowman ☃', 'n': 42, 'yes': True, 'none': None}
        self.assertEqual(decode_object(encode_object(good)), good)
        for raw in (b'[]', b'null', b'{"a":1,"a":2}', b'{"x":NaN}',
                    b'{"x":1.5}', b'{"x":1e999}', b'{"x":9223372036854775808}',
                    b'{"x":"\\ud800"}', b'{"x":"\xff"}', b'{} trailing'):
            with self.subTest(raw=raw):
                with self.assertRaises(ProtocolError):
                    decode_object(raw)

    def test_direct_values_bounds_and_cycles(self):
        cycle = {}; cycle['cycle'] = cycle
        for value in (cycle, {'x': object()}, {'x': float('nan')},
                      {'x': 'x'*(MAX_LINE_BYTES+1)}, {'x': [None]*MAX_ARG_NODES}):
            with self.assertRaises(ProtocolError):
                encode_object(value)
        value = {}
        for _ in range(MAX_ARG_DEPTH+1):
            value = {'x': value}
        with self.assertRaises(ProtocolError):
            encode_object(value)

    def pipes(self):
        incoming, writer = os.pipe()
        reader, outgoing = os.pipe()
        for fd in (incoming, writer, reader, outgoing):
            self.addCleanup(os.close, fd)
        return incoming, writer, reader, outgoing

    def test_multiple_frames_and_modes_restored(self):
        incoming, writer, reader, outgoing = self.pipes()
        os.write(writer, b'{"x":1}\n{"x":2}\n')
        with JsonLines(incoming, outgoing, .1) as lines:
            self.assertEqual(lines.read(), {'x': 1})
            self.assertEqual(lines.read(), {'x': 2})
            lines.write({'ok': True})
            self.assertEqual(os.read(reader, 100), b'{"ok":true}\n')
        self.assertTrue(os.get_blocking(incoming))
        self.assertTrue(os.get_blocking(outgoing))

    def test_stalled_read_and_write_deadlines(self):
        incoming, writer, reader, outgoing = self.pipes()
        with JsonLines(incoming, outgoing, .05) as lines:
            start = time.monotonic()
            with self.assertRaises(ProtocolError):
                lines.read()
            self.assertLess(time.monotonic()-start, 1)
            while True:
                try:
                    os.write(outgoing, b'x'*4096)
                except BlockingIOError:
                    break
            start = time.monotonic()
            with self.assertRaises(ProtocolError):
                lines.write({'ok': True})
            self.assertLess(time.monotonic()-start, 1)

    def test_unterminated_frame_refuses_on_eof(self):
        incoming, writer = os.pipe()
        reader, outgoing = os.pipe()
        try:
            os.write(writer, b'{"x":1}')
            os.close(writer)
            with JsonLines(incoming, outgoing, .1) as lines:
                with self.assertRaises(ProtocolError):
                    lines.read()
        finally:
            for fd in (incoming, reader, outgoing):
                os.close(fd)

    def test_exact_limit_split_frame_and_overflow(self):
        for extra in (0, 1):
            incoming, writer, reader, outgoing = self.pipes()
            frame = b'{"x":"' + b'a'*(MAX_LINE_BYTES-8+extra) + b'"}\n'
            failures = []
            def send():
                try:
                    offset = 0
                    while offset < len(frame):
                        offset += os.write(writer, frame[offset:offset+4096])
                except OSError as error:
                    failures.append(type(error).__name__)
            thread = threading.Thread(target=send, daemon=True)
            thread.start()
            with JsonLines(incoming, outgoing, 1) as lines:
                if extra:
                    with self.assertRaises(ProtocolError):
                        lines.read()
                else:
                    self.assertEqual(lines.read(), {'x': 'a'*(MAX_LINE_BYTES-8)})
            thread.join(2)
            self.assertFalse(thread.is_alive())
            self.assertFalse(failures)

    def test_invalid_descriptor_has_fixed_failure(self):
        with self.assertRaises(ProtocolError):
            with JsonLines(10**10000, 1):
                self.fail('Invalid descriptor accepted')

    def test_empty_stream_and_invalid_deadlines(self):
        incoming, writer = os.pipe()
        os.close(writer)
        try:
            with JsonLines(incoming, 1, .1) as lines:
                self.assertIsNone(lines.read())
            for timeout in (True, 0, -1, float('inf'), float('nan'),
                            MAX_PROCESS_SECONDS+1, 10**10000):
                with self.assertRaises(ProtocolError):
                    JsonLines(incoming, 1, timeout)
        finally:
            os.close(incoming)


if __name__ == '__main__':
    unittest.main()
