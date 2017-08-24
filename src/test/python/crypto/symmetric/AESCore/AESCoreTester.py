import cocotb
from cocotb.triggers import Timer, Edge, RisingEdge

from cocotblib.ClockDomain import ClockDomain, RESET_ACTIVE_LEVEL
from cocotblib.Stream import Stream
from cocotblib.Flow import Flow
from cocotblib.misc import randBits, assertEquals


class AESCoreHelper:

    def __init__(self,dut):
        self.io = AESCoreHelper.IO(dut)

    class IO:

        def __init__ (self, dut):
            self.cmd    = Stream(dut, "io_crypto_cmd")
            self.rsp    = Flow(dut, "io_crypto_rsp")
            self.clk    = dut.clk
            self.resetn = dut.resetn

        def init(self):
            self.cmd.valid          <= 0
            self.cmd.payload.block  <= 0
            self.cmd.payload.key    <= 0
            self.cmd.payload.enc    <= 0


@cocotb.test()
def testAESCore(dut):
    dut.log.info("Cocotb test AES Core Start")

    from cocotblib.misc import cocotbXHack
    cocotbXHack()

    helperAES    = AESCoreHelper(dut)
    clockDomain  = ClockDomain(helperAES.io.clk, 200, helperAES.io.resetn , RESET_ACTIVE_LEVEL.LOW)

    # Start clock
    cocotb.fork(clockDomain.start())

    # Init IO and wait the end of the reset
    helperAES.io.init()
    yield clockDomain.event_endReset.wait()

    # start monitoring the Valid signal
    helperAES.io.rsp.startMonitoringValid(helperAES.io.clk)


    key = 0x2b7e151628aed2a6abf7158809cf4f3c
    data = 0x6bc1bee22e409f96e93d7e117393172a

    # Encrpytion
    helperAES.io.cmd.valid          <= 1
    helperAES.io.cmd.payload.key    <= key
    helperAES.io.cmd.payload.block  <= data
    helperAES.io.cmd.payload.enc    <= 1  # do an encryption

    # Wait the end of the process and read the result
    yield helperAES.io.rsp.event_valid.wait()
    rtlEncryptedBlock = int(helperAES.io.rsp.event_valid.data.block)

    #print("RTL encrypted", hex(rtlEncryptedBlock))
    helperAES.io.cmd.valid         <= 0

    yield RisingEdge(helperAES.io.clk)

    # expected result:
    result = 0x3ad77bb40d7a3660a89ecaf32466ef97


    dut.log.info("Cocotb test AES Core End")