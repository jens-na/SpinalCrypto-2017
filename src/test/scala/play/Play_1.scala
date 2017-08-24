package play

import spinal.core._
import spinal.lib._
import spinalcrypto.hash._
import spinalcrypto.hash.md5._
import spinalcrypto.mac.hmac.{HMACCoreStdGeneric, HMACCoreStdIO, HMACCore_Std}
import spinalcrypto.symmetric.SymmetricCryptoBlockIO
import spinalcrypto.symmetric.des.{DESCore_Std, TripleDESCore_Std}



object PlayWithDesCore_Std{

  class DESCoreStdTester extends Component {

    val des = new DESCore_Std()

    val io  = slave(new SymmetricCryptoBlockIO(des.gIO))

    des.io <> io
  }

  def main(args: Array[String]): Unit = {
    SpinalConfig(
      mode = Verilog,
      dumpWave = DumpWaveConfig(depth = 0),
      defaultConfigForClockDomains = ClockDomainConfig(clockEdge = RISING, resetKind = ASYNC, resetActiveLevel = LOW),
      defaultClockDomainFrequency = FixedFrequency(50 MHz)
    ).generate(new DESCoreStdTester).printPruned
  }
}

/*
object PlayWith3DesCore_Std{

  class TripleDESCoreStdTester extends Component {

    val des3 = new TripleDESCore_Std()

    val io = slave(new SymmetricCryptoBlockIO(des3.gIO))

    des3.io <> io
  }

  def main(args: Array[String]): Unit = {
    SpinalConfig(
      mode = Verilog,
      dumpWave = DumpWaveConfig(depth = 0),
      defaultConfigForClockDomains = ClockDomainConfig(clockEdge = RISING, resetKind = ASYNC, resetActiveLevel = LOW),
      defaultClockDomainFrequency = FixedFrequency(50 MHz)
    ).generate(new TripleDESCoreStdTester).printPruned
  }
}


object PlayWithMD5Core_Std{

  class MD5CoreStdTester extends Component{

    val md5 = new MD5Core_Std()

    val io = slave(HashCoreIO(md5.g))

    md5.io <> io
  }

  def main(args: Array[String]): Unit = {
    SpinalConfig(
      mode = Verilog,
      dumpWave = DumpWaveConfig(depth = 0),
      defaultConfigForClockDomains = ClockDomainConfig(clockEdge = RISING, resetKind = ASYNC, resetActiveLevel = LOW),
      defaultClockDomainFrequency = FixedFrequency(50 MHz)
    ).generate(new MD5CoreStdTester).printUnused()
  }
}

object PlayWithHMACCore_Std_MD5Core_Std{

  class HMACCoreStdTester() extends Component{

    val md5  = new MD5Core_Std()
    val hmac = new HMACCore_Std(HMACCoreStdGeneric(md5.g.hashBlockWidth, md5.g))

    val io = slave(HMACCoreStdIO(hmac.g))

    hmac.io.hmacCore <> io
    hmac.io.hashCore <> md5.io
  }

  def main(args: Array[String]): Unit = {
    SpinalConfig(
      mode = Verilog,
      dumpWave = DumpWaveConfig(depth = 0),
      defaultConfigForClockDomains = ClockDomainConfig(clockEdge = RISING, resetKind = ASYNC, resetActiveLevel = LOW),
      defaultClockDomainFrequency = FixedFrequency(50 MHz)
    ).generate(new HMACCoreStdTester).printPruned
  }
}*/