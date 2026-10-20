import ctypes as ct
import unittest

from monitors.ebpf_process import ARG_COUNT, ARG_SIZE, _argv_bytes, _decode_argv


class EventT(ct.Structure):
    # Mirrors the BPF struct_event_t so the decoder can run without a kernel.
    _fields_ = [("pid", ct.c_uint), ("ppid", ct.c_uint), ("type", ct.c_uint),
                ("comm", ct.c_char * 16),
                ("argv", ct.c_char * (ARG_COUNT * ARG_SIZE)),
                ("argv_truncated", ct.c_uint), ("pid_ns", ct.c_uint)]


def event_for(args):
    blob = bytearray(ARG_COUNT * ARG_SIZE)
    for index, arg in enumerate(args):
        encoded = arg.encode()[:ARG_SIZE - 1]
        blob[index * ARG_SIZE:index * ARG_SIZE + len(encoded)] = encoded
    event = EventT(type=1)
    # The kernel writes this region directly; a ctypes assignment would stop at a NUL.
    ct.memmove(ct.byref(event, EventT.argv.offset), bytes(blob), len(blob))
    return event


class ArgvDecodeTests(unittest.TestCase):
    def decode(self, args):
        return _decode_argv(_argv_bytes(event_for(args)))

    def test_arguments_after_the_first_survive(self):
        # Reading the argv field through ctypes yields only argv[0], which leaves
        # rules that inspect later arguments (such as subshell) unable to match.
        self.assertEqual(self.decode(["bash", "-c", "curl -s http://example.com"]),
                         ["bash", "-c", "curl -s http://example.com"])

    def test_empty_argv(self):
        self.assertEqual(self.decode([]), [])

    def test_all_slots_used(self):
        self.assertEqual(len(self.decode([f"a{i}" for i in range(ARG_COUNT)])), ARG_COUNT)

    def test_long_argument_is_capped(self):
        self.assertEqual(len(self.decode(["x" * 500])[0]), ARG_SIZE - 1)


if __name__ == "__main__":
    unittest.main()
