import pathlib
import subprocess
import sys
import tempfile
import unittest

import struct
import zlib

from build_blocklist import HASH_BYTES, fnv

HDR = 16


def payload_of(data):
    assert data[:4] == b'C3BL', 'missing C3BL header'
    ver, hb, _res, count, crc = struct.unpack('<BBHII', data[4:HDR])
    body = data[HDR:]
    assert (ver, hb) == (1, HASH_BYTES) and len(body) == count * HASH_BYTES and zlib.crc32(body) == crc
    return body


class BuildBlocklistTests(unittest.TestCase):
    def test_hosts_line_includes_every_domain(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            source = root / 'hosts'
            output = root / 'blocklist.bin'
            source.write_text('0.0.0.0 ads.example.com tracker.example.com # comment\n'
                              '127.0.0.1 metrics.example.com\n', encoding='utf-8')

            subprocess.run([sys.executable, str(pathlib.Path(__file__).with_name('build_blocklist.py')),
                            str(output), str(source)], check=True, capture_output=True, text=True)

            data = payload_of(output.read_bytes())
            hashes = {int.from_bytes(data[i:i + HASH_BYTES], 'little')
                      for i in range(0, len(data), HASH_BYTES)}
            expected = {fnv(domain.encode()) for domain in
                        ('ads.example.com', 'tracker.example.com', 'metrics.example.com')}
            self.assertEqual(hashes, expected)

    def run_build(self, text):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            source, output = root / 'list.txt', root / 'blocklist.bin'
            source.write_text(text, encoding='utf-8')
            subprocess.run([sys.executable, str(pathlib.Path(__file__).with_name('build_blocklist.py')),
                            str(output), str(source)], check=True, capture_output=True, text=True)
            data = payload_of(output.read_bytes())
            return {int.from_bytes(data[i:i + HASH_BYTES], 'little') for i in range(0, len(data), HASH_BYTES)}

    def test_subdomain_of_listed_parent_is_dropped(self):
        got = self.run_build('ads.example.com\nx.ads.example.com\ny.z.ads.example.com\nother.net\n')
        self.assertEqual(got, {fnv(b'ads.example.com'), fnv(b'other.net')})

    def test_child_kept_when_parent_is_allowlisted(self):
        got = self.run_build('||example.com^\n||ads.example.com^\n@@||example.com^\n')
        self.assertEqual(got, {fnv(b'ads.example.com')})

    def test_junk_names_are_dropped(self):
        got = self.run_build('0.0.0.0 0.0.0.0\n0.0.0.0 -bad.gif\n10.1.2.3\ngood.example.com\n')
        self.assertEqual(got, {fnv(b'good.example.com')})

    def test_raw_flag_writes_bare_hashes(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            source, output = root / 'list.txt', root / 'blocklist.bin'
            source.write_text('ads.example.com\n', encoding='utf-8')
            subprocess.run([sys.executable, str(pathlib.Path(__file__).with_name('build_blocklist.py')),
                            '--raw', str(output), str(source)], check=True, capture_output=True, text=True)
            self.assertEqual(output.read_bytes(), fnv(b'ads.example.com').to_bytes(HASH_BYTES, 'little'))


if __name__ == '__main__':
    unittest.main()
