package testbench

import spinal.core._
import spinal.lib._
import spinal.lib.bus.amba3.apb._
import spinal.lib.bus.amba4.axi._
import spinal.lib.io.TriStateArray
import spinalcrypto.symmetric.des._
import spinalcrypto.hash.md5._
import spinalcrypto.mac.hmac._

object Apb3_TestBenchConfig{
  def getApb3Config = Apb3Config(
    addressWidth  = 10,
    dataWidth     = 32,
    selWidth      = 1,
    useSlaveError = false
  )
}


case class Apb3_DESCore() extends Component{

  val io = new Bundle{
    val apb       = slave(Apb3(Apb3_TestBenchConfig.getApb3Config))
  }

  val desCore = new DESCore_Std()

  val busCtrl = Apb3SlaveFactory(io.apb)
  desCore.io.driveFrom(busCtrl)
}


case class APB3_3DESCore() extends Component{

  val io = new Bundle{
    val apb       = slave(Apb3(Apb3_TestBenchConfig.getApb3Config))
  }

  val desCore = new TripleDESCore_Std()

  val busCtrl = Apb3SlaveFactory(io.apb)
  desCore.io.driveFrom(busCtrl)
}

case class APB3_MD5() extends Component{

  val io = new Bundle{
    val apb       = slave(Apb3(Apb3_TestBenchConfig.getApb3Config))
  }

  val md5Core = new MD5Core_Std()

  val busCtrl = Apb3SlaveFactory(io.apb)
  md5Core.io.driveFrom(busCtrl)
}


case class APB3_HMAC_MD5() extends Component{

  val io = new Bundle{
    val apb       = slave(Apb3(Apb3_TestBenchConfig.getApb3Config))
  }

  val md5Core  = new MD5Core_Std()
  val hmacCore = new HMACCore_Std(HMACCoreStdGeneric(md5Core.g.hashBlockWidth, md5Core.g))

  hmacCore.io.hashCore <> md5Core.io

  val busCtrl = Apb3SlaveFactory(io.apb)
  hmacCore.io.hmacCore.driveFrom(busCtrl)

}





class TestBench_APB_1 extends Component{

  val axi4Config = Axi4Config(addressWidth = 32,
                              dataWidth    = 32,
                              idWidth      = 2,
                              useId        = true,
                              useRegion    = false,
                              useBurst     = true,
                              useLock      = false,
                              useCache     = false,
                              useSize      = true,
                              useQos       = false,
                              useLen       = true,
                              useLast      = true,
                              useResp      = true,
                              useProt      = false,
                              useStrb      = true,
                              useUser      = false,
                              userWidth    = -1)

  val io = new Bundle{
    val axiClk    = in Bool
    val axiRstn   = in Bool

    val axi       = slave(Axi4(axi4Config))

    val gpioA     = master(TriStateArray(32 bits))
  }


  val axiClockDomain = ClockDomain(
    clock = io.axiClk,
    reset = io.axiRstn
  )


  val axi = new ClockingArea(axiClockDomain) {

    val apbBridge = Axi4SharedToApb3Bridge(
      addressWidth = 32,
      dataWidth    = 32,
      idWidth      = 2
    )

    val gpioACtrl = Apb3Gpio(
      gpioWidth = 32
    )

    val desCore       = Apb3_DESCore()
    val tripleDESCore = APB3_3DESCore()
    val md5Core       = APB3_MD5()
    val hmacMD5       = APB3_HMAC_MD5()


    apbBridge.io.axi <> Axi4ToAxi4Shared(io.axi)

    val apbDecoder = Apb3Decoder(
      master = apbBridge.io.apb,
      slaves = List(
        gpioACtrl.io.apb     -> (0x0000, 1 kB),
        desCore.io.apb       -> (0x1000, 1 kB),
        tripleDESCore.io.apb -> (0x2000, 1 kB),
        hmacMD5.io.apb       -> (0x3000, 1 kB),
        md5Core.io.apb       -> (0x4000, 1 kB)
      )
    )
  }

  io.gpioA  <> axi.gpioACtrl.io.gpio
}


object PlayWithTestBench_APB_1{
  def main(args: Array[String]): Unit = {
    SpinalConfig(
      mode = VHDL,
      dumpWave = DumpWaveConfig(depth = 0),
      defaultConfigForClockDomains = ClockDomainConfig(clockEdge = RISING, resetKind = ASYNC, resetActiveLevel = LOW),
      defaultClockDomainFrequency = FixedFrequency(50 MHz)
    ).generate(new TestBench_APB_1).printPruned
  }
}