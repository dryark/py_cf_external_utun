# Copyright (c) 2024 Dry Ark LLC
# License AGPL 3.0
import asyncio
import os
import subprocess
import time
import signal
import struct
import sys

from socket import (
    AF_INET6,
)

from typing import (
    Callable,
)


IPV6_HEADER_SIZE = 40
UDP_HEADER_SIZE = 8

if sys.platform == 'darwin':
    UTUN_INET6_HEADER = struct.pack('>I', AF_INET6)
else:
    # Ethertype 0x86DD :  Internet Protocol Version 6 (IPv6)
    UTUN_INET6_HEADER = b'\x00\x00\x86\xdd'

UTUN_INET6_HEADER_SIZE = len(UTUN_INET6_HEADER)

class ExternalUtun():
    def __init__(self):
        self.process = None
        self.utun = ""
        self.output_thread = None
        self.uds_path = "/tmp/myuds"
        self.label = "label"
        self.loop = None
        self.writer = None
        self.name = ""
        if 'CFUTUNUDS' in os.environ:
            self.utunudsPath = os.environ['CFUTUNUDS']
        elif 'CFTOOLS' in os.environ:
            self.utunudsPath = os.environ['CFTOOLS'] + "/utunuds"
        else:
            self.utunudsPath = "utunuds"
        #self.isup = True
        self._writer_ready = asyncio.Event()
        
    async def handle_stdout(self,stream):
        print('Starting to read from process')
        while True:
            line = await stream.readline()
            line = line.decode('utf-8')
            #line = line.replace('-', '  ')
            if not line:
                break
            print("Utunuds:", line )  # Debugging output
            #if line.startswith('utun:') and self.utun is None:
            #    self.utun = line.strip().split('utun:')[1]
            #    self.name = self.utun
    
    async def handle_stderr(self, stream):
        try:
            while True:
                line = await stream.readline()
                if not line:
                    break
                print("Stderr:", line.strip())  # Debugging output
        except Exception as e:
            print("Error reading stream:", e)
        finally:
            pass
    
    async def handle_uds_client(self,reader, writer):
        #print('uds client begin')
        self.writer = writer
        self._writer_ready.set()  # Signal that the writer is ready

        def fail(reason):
            print(reason + ".  Generating SIGINT to shut down.")
            os.kill(os.getpid(), signal.SIGINT)

        while True:
            try:
                # We need to deliver each IPV6 frame as a single unit to be passed to the quic
                # tunnel.  Our frames may be interleaved with other quic data (for example,
                # a quic "ping"), so if we just try to deliver what we read here as a binary
                # blob, we'll encounter random failures.
                #
                # In the case of simply reading a binary stream here, we may also introduce MTU
                # issues by reading several IPV6 packets at once, even if all of the data was otherwise
                # passed without mangling or interruption.
                #
                # It seems a little circuitous, but we strip the UTUN_INET6_HEADER here, the
                # remaining IPV6 frame gets passed around as a Datagram, before the UTUN_INET6_HEADER
                # gets stuck back on before being pushed down the wire...

                # Note: readexactly() wiil raise IncompleteReadError if the reader is closed.
                datagram_type = await reader.readexactly(UTUN_INET6_HEADER_SIZE)

                # If someone dumps garbage into the tunnel, we really have no way to recover
                if datagram_type != UTUN_INET6_HEADER:
                    fail("Read non-IPV6 data from unix domain socket.")
                    break

                ipv6_header = await reader.readexactly(IPV6_HEADER_SIZE)
                ipv6_length = struct.unpack('>H', ipv6_header[4:6])[0]
                ipv6_body = await reader.readexactly(ipv6_length)

                # Our current callback immediately strips "datagram_type".  We could just leave
                # it off here, since we currently support only IPv6.  But perhaps some other message
                # type may be needed in the future, so for consistency, for now, we'll just pass it along.
                # (If this library is used more generically, the IPV6 limitation could be expanded)
                data = datagram_type + ipv6_header + ipv6_body
                # print("Read %d bytes from reader. Decoded size is %d" % (len(data), ipv6_length) )
                await self.callback(data)
            except Exception as e:
                fail("Exception encountered reading from unix domain socket. " + repr(e))
                break
        if self.writer:
            writer.close()
    
    async def start_uds( self, path ):
        await asyncio.start_unix_server( self.handle_uds_client, path=path )
    
    def write( self, data ):
        if self.writer is not None:
            self.writer.write(data)
        else:
            print("Connection to UDS not established or already closed.")
    
    async def up(
        self,
        label:str,
        ipv6:str,
        incoming_data_callback: Callable[[str], None]
    ) -> str:
        self.uds_path = f'/tmp/utunuds_{label}'
        self.callback = incoming_data_callback
        
        if self.process is not None and self.process.poll() is None:
            print("Process is already running.")
            return ""
        
        await self.start_uds( self.uds_path )
        
        time.sleep(0.05)
        
        #print( f'calling utunuds with uds={uds_path} and ipv6={ipv6}' )
        self.process = await asyncio.create_subprocess_exec(
            *[self.utunudsPath, self.uds_path, ipv6],
            stdin=asyncio.subprocess.PIPE, # We open stdin so that utunds will get EOF when we close it
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

        # This fixes a race condition. We're not really "up" until we can write data to the
        # tunnel (see .writer initialization in handle_uds_client).  Otherwise, we risk being
        # asked to send data that we cannot forward. (triggering "UDS not established or already closed.")
        try:
            await asyncio.wait_for(self._writer_ready.wait(), 3.0)
        except asyncio.TimeoutError:
            print("Failed to initialize unix domain socket connection")
        
        loop = asyncio.get_event_loop()
        loop.create_task( self.handle_stdout( self.process.stdout ) )
        loop.create_task( self.handle_stdout( self.process.stderr ) )
        
        return self.utun
    
    def down(self) -> None:
        if not self.process:
            return
        if self.writer:
            self.writer.close()

        # We generally cannot terminate this process explicitly, as it was launched 'suid root', and
        # we are not root.  It should exit gracefully as we close stdin. (or die for other reasons,
        # with stdin being closed by the OS)
        # self.process.terminate()
        self.process.stdin.close()
        self.process = None
        self.writer = None

    def __del__(self):
        self.down()
