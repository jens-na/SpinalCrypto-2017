package cryptotest

import spinal.core._
import spinal.lib._
import spinalcrypto.symmetric.aes._
import spinalcrypto.symmetric._

class AESCoreTester extends Component {
  val aes = new AESCore(128, 128)

  val io = new Bundle {
    val crypto = slave(new SymmetricCryptoBlockIO(aes.gIO))
    val round = out UInt(log2Up(10) bits)
    val state = out Vec(Vec(Bits(8 bits), 4), 4)
    val cipherState = out (AESState)
    val inputBlock = out Vec(Bits(8 bits), 16)
    val roundKeys = out Vec(Bits(8 bits), (4 * (10 + 1) * 4))
  }

  aes.io.crypto <> io.crypto
  io.round := aes.io.round
  io.state := aes.io.state
  io.cipherState := aes.io.cipherState
  io.inputBlock := aes.io.inputBlock
  io.roundKeys := aes.io.roundKeys
}

class AESCoreCocotbBoot extends SpinalTesterCocotbBase {
  override def getName: String = "AESTester"
  override def pythonTestLocation: String = "src/test/python/crypto/symmetric/AESCore"
  override def createToplevel: Component = new AESCoreTester
  override def backendConfig(config: SpinalConfig): SpinalConfig = {
    config.copy(defaultClockDomainFrequency  = FixedFrequency(50 MHz),
      defaultConfigForClockDomains = ClockDomainConfig(clockEdge = RISING, resetKind = ASYNC, resetActiveLevel = LOW))
  }
}
