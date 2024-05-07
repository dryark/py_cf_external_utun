# Copyright (c) 2024 Dry Ark LLC
# Anti-Corruption License
import asyncio
import os
import subprocess
import time

from typing import (
    Callable,
)

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
        if 'CFTOOLS' in os.environ:
            self.utunudsPath = os.environ['CFTOOLS'] + "/utunuds"
        else:
            if 'CFUTUNUDS' in os.environ:
                self.utunudsPath = os.environ['CFUTUNUDS']
            else:
                self.utunudsPath = "utunuds"
        #self.isup = True
        
    async def handle_stdout(self,stream):
        print('Starting to read from process')
        while True:
            line = await stream.readline()
            if not line:
                break
            print("Output:", line.strip())  # Debugging output
            if line.startswith('utun:') and self.utun is None:
                self.utun = line.strip().split('utun:')[1].strip()
                self.name = self.utun
    
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
        while True:
            data = await reader.read(1500)
            if not data:
                break
            await self.callback(data)
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
        
        #loop = asyncio.get_event_loop()
        #loop.create_task( self.handle_stdout( self.process.stdout ) )
        #loop.create_task( self.handle_stdout( self.process.stderr ) )
        
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
