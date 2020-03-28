from urllib.parse import urlparse, parse_qs
from distutils.util import strtobool
from rekall import addrspace

import os
import re

qmp = None
try:
    import qmp
except ImportError:
    pass

SCHEME = 'qmp'

class QMPAddressSpace(addrspace.BaseAddressSpace):
    """An address space which operates on top of qemu's qmp interface."""

    __abstract = False
    __name = "qmp"
    order = 90
    volatile = True
    __image = True

    def __init__(self, base=None, filename=None, session=None, **kwargs):
        self.as_assert(qmp, "The qmp python bindings must be installed")
        self.as_assert(base is None, "must be first Address Space")
        self.session = session

        url = filename or (session and session.GetParameter("filename"))
        self.as_assert(url, "Filename must be specified in session (e.g. "
                "session.SetParameter('filename', 'qmp:///hostname:port').")
        qmp_url = urlparse(url)

        self.as_assert(qmp_url.scheme == SCHEME, "URL scheme must be qmp://")
        self.as_assert(qmp_url.hostname, "No hostname specified")
        self.as_assert(qmp_url.port, "No port specified")

        hostname = qmp_url.hostname
        port = qmp_url.port

        self.mode = None
        self.volatile = True
        self.datapath = '/tmp/qmp_'+qmp_url.hostname+'_'+str(qmp_url.port)

        super(QMPAddressSpace, self).__init__(base=base, session=session,
                                              **kwargs)

        self.qmp = qmp.QEMUMonitorProtocol((hostname, port))
        c = self.qmp.connect()

        r = self.qmp.cmd('human-monitor-command', { "command-line" : "info memory_size_summary" })
        m = re.match('base memory: ([0-9]+)', r['return'])

        self.min_addr = 0
        self.max_addr = int(m.group(1)) - 1
        
        # register flush hook to destroy instance when session.Flush() is called
        session.register_flush_hook(self, self.close)

    def close(self):
        pass

    def read(self, addr, size):

        r = self.qmp.cmd('pmemsave', { "val": addr, "size": size, "filename": self.datapath })
        try:
            r['return']
            fd = os.open(self.datapath, os.O_RDONLY)
            data = os.read(fd, size)
            os.close(fd)
            return data
        except:
            return b''

    def write(self, addr, data):
        return False

    def is_valid_address(self, addr):
        if addr is None:
            return False
        return self.min_addr <= addr <= self.max_addr

    def get_available_addresses(self):
        yield (self.min_addr, self.max_addr)

    def get_mappings(self, start=0, end=2 ** 64):
        yield addrspace.Run(start=self.min_addr, end=self.max_addr,
                            file_offset=0, address_space=self)
