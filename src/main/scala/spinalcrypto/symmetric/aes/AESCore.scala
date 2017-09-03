package spinalcrypto.symmetric.aes

import spinal.core._
import spinal.lib._
import spinal.lib.fsm._
import spinalcrypto.symmetric.{SymmetricCryptoBlockGeneric, SymmetricCryptoBlockIO}

/**
  * AES core component
  */
class AESCore(keyLength : Int, blockLength: Int) extends Component {


  def xtimes(x : Bits) : Bits = {
    return (x<<1).resize(8) ^ (((x>>7) & 1).asUInt * 0x1b).asBits.resize(8)
  }

  def resize8(x : UInt) : UInt = {
    return x.resize(8)
  }

  // Symmetric crypto API
  val gIO = SymmetricCryptoBlockGeneric(keyWidth = BitCount(keyLength),
                                        blockWidth = BitCount(blockLength),
                                        useEncDec = true)

  // AES config
  val nb = blockLength / 32
  val nk = keyLength / 32
  val nr = if(keyLength == 128) 10 else if(keyLength == 192) 12 else 14
  val keyCount = nb * (nr + 1) * 4


  val io = new Bundle {

    val crypto = slave(new SymmetricCryptoBlockIO(gIO))

    val state = out Vec(Vec(Bits(8 bits), 4), 4)
    val round = out UInt(log2Up(nr) bits)
    val cipherState = out (AESState)

    val inputBlock = out Vec(Bits(8 bits), 16)
    val roundKeys = out Vec(Bits(8 bits), keyCount)
  }

  val encode = io.crypto.cmd.enc

  // Cipher state
  val cipherState = Reg(AESState) init(AESState.Init)
  io.cipherState := cipherState

  // 4x4 state matrix
  val state = Reg(Vec(Vec(Bits(8 bits), 4), 4))
  io.state := state

  val respValid  = False

  // Round evaluation
  val round = UInt(log2Up(nr) bits)
  io.round := round

  // Round: 0
  val initRound = io.crypto.cmd.valid.rise(False)

  // Round: N
  val lastRound = (round === nr)

  // Round: 0 < Round < N
  val hasNextRound = Reg(Bool) init(False) setWhen(initRound) clearWhen(lastRound)

  /**
    * Round counter
    */
  val roundCounter = new Area {
    val round = Reg(UInt(log2Up(nr) bits))

    when(cipherState === AESState.Init) {
      round := U(0)
    }
    when(cipherState === AESState.AddRoundKey) {
      round := round + 1
    }
  }
  round := roundCounter.round

  //
  //
  //
  val F = new Area {
    val inputBlock = Vec(Bits(8 bits), 16)
    val inputKey = Vec(Bits(8 bits), 16)

    inputKey(0) := io.crypto.cmd.key(127 downto 120)
    inputBlock(0) := io.crypto.cmd.block(127 downto 120)
    for(i <- 1 until 16) {
      inputKey(i) := io.crypto.cmd.key(127-(i*7)-i downto 127-((i+1)*7)-i)
      inputBlock(i) := io.crypto.cmd.block(127-(i*7)-i downto 127-((i+1)*7)-i)
    }
  }
  io.inputBlock := F.inputBlock

  //
  //
  //
  val R = new Area {
    val responseBlock = Bits(128 bits)

    //responseBlock := ((127 downto 120) -> state(4)(4), default -> false)
    //responseBlock := ((7 downto 0) -> state(0)(0), default -> false)
    var k = 0
    for(i <- 0 until 4) {
      for(j <- 0 until 4) {
        responseBlock := ((127-(k*7)-k downto 127-((k+1)*7)-k) -> state(i)(j))
        k = k + 1
      }
    }

  }

  /**
    * The lookup tables for AES
    */
  val Tables = new Area {
    val sbox = Mem(Bits(8 bits), AESCoreSpec.sbox.map(B(_, 8 bits)))
    val rsbox = Mem(Bits(8 bits), AESCoreSpec.rsbox.map(B(_, 8 bits)))
    val rcon = Mem(Bits(8 bits), AESCoreSpec.rcon.map(B(_, 8 bits)))
  }



  /**
    * KeyExpansion function: for 'nr' keys. First key is always the key which is
    * provided by io.crypto.key.
    */
  val KeyExpansion = new Area {
    val roundKeys = Reg(Vec(Bits(8 bits), keyCount))
    val fire = cipherState === AESState.KeyExpansion
    val isBusy = Reg(Bool) init(False)


    val next = Reg(UInt(log2Up(keyCount) bits )) init(nk)
    val cur = resize8(next * 4)
    val prev1 = resize8((next - 1) * 4)
    val prev16 = resize8((next - nk) * 4)
    val rconCalc = resize8(next / nk)


    when(isBusy) {
      when(next < (nb * (nr + 1))) {
        when(next % nk === 0) {
          roundKeys(cur + 0) := roundKeys(prev16 + 0) ^ (Tables.sbox.readAsync(roundKeys(prev1 + 1).asUInt)  ^ Tables.rcon.readAsync(rconCalc))
          roundKeys(cur + 1) := roundKeys(prev16 + 1) ^ Tables.sbox.readAsync(roundKeys(prev1 + 2).asUInt)
          roundKeys(cur + 2) := roundKeys(prev16 + 2) ^ Tables.sbox.readAsync(roundKeys(prev1 + 3).asUInt)
          roundKeys(cur + 3) := roundKeys(prev16 + 3) ^ Tables.sbox.readAsync(roundKeys(prev1 + 0).asUInt)
        }.otherwise {
          roundKeys(cur + 0) := roundKeys(prev16 + 0) ^ roundKeys(prev1 + 0)
          roundKeys(cur + 1) := roundKeys(prev16 + 1) ^ roundKeys(prev1 + 1)
          roundKeys(cur + 2) := roundKeys(prev16 + 2) ^ roundKeys(prev1 + 2)
          roundKeys(cur + 3) := roundKeys(prev16 + 3) ^ roundKeys(prev1 + 3)
        }

        //AES256
        // when(Bool(nk > 6) && next % nk === 4) {
        //  roundKeys((next * 4) + 0) := roundKeys((next - nk) * 4 + 0) ^ Tables.sbox.readAsync(roundKeys((next - 1) * 4 + 0).asUInt)
        //  roundKeys((next * 4) + 1) := roundKeys((next - nk) * 4 + 1) ^ Tables.sbox.readAsync(roundKeys((next - 1) * 4 + 1).asUInt)
        //  roundKeys((next * 4) + 2) := roundKeys((next - nk) * 4 + 2) ^ Tables.sbox.readAsync(roundKeys((next - 1) * 4 + 2).asUInt)
        //  roundKeys((next * 4) + 3) := roundKeys((next - nk) * 4 + 3) ^ Tables.sbox.readAsync(roundKeys((next - 1) * 4 + 3).asUInt)
        //}

        next := next + 1
      }.otherwise {
        isBusy := False
      }
    }
  }

  io.roundKeys := KeyExpansion.roundKeys

  val MixColumns = new Area {
    val fire = cipherState === AESState.MixColumns

    when(fire) {
      val tmp = Vec(Bits(8 bits), 4)
      val tm1 = Vec(Bits(8 bits), 4)
      val tm2 = Vec(Bits(8 bits), 4)
      val tm3 = Vec(Bits(8 bits), 4)
      val tm4 = Vec(Bits(8 bits), 4)
      val t = Vec(Bits(8 bits), 4)

      for(i <- 0 until 4) {
        t(i) := state(i)(0)
        tmp(i) := state(i)(0) ^ state(i)(1) ^ state(i)(2) ^ state(i)(3)

        tm1(i) := xtimes(state(i)(0) ^ state(i)(1))
        state(i)(0) := state(i)(0) ^ tm1(i) ^ tmp(i)

        tm2(i) := xtimes(state(i)(1) ^ state(i)(2))
        state(i)(1) := state(i)(1) ^ tm2(i) ^ tmp(i)

        tm3(i) := xtimes(state(i)(2) ^ state(i)(3))
        state(i)(2) := state(i)(2) ^ tm3(i) ^ tmp(i)

        tm4(i) := xtimes(state(i)(3) ^ t(i))
        state(i)(3) := state(i)(3) ^ tm4(i) ^ tmp(i)

      }

    }
  }

  val ShiftRows = new Area {
    val fire = cipherState === AESState.ShiftRows

    val tempStates = Vec(Bits(8 bits), 4)
    tempStates(0) := state(0)(1)
    tempStates(1) := state(0)(2)
    tempStates(2) := state(1)(2)
    tempStates(3) := state(0)(3)

    when(fire) {
      state(0)(1) := state(1)(1)
      state(1)(1) := state(2)(1)
      state(2)(1) := state(3)(1)
      state(3)(1) := tempStates(0)

      state(0)(2) := state(2)(2)
      state(2)(2) := tempStates(1)

      state(1)(2) := state(3)(2)
      state(3)(2) := tempStates(2)

      state(0)(3) := state(3)(3)
      state(3)(3) := state(2)(3)
      state(2)(3) := state(1)(3)
      state(1)(3) := tempStates(3)
    }
  }

  val SubBytes = new Area {
    val fire = cipherState === AESState.SubBytes

    when(fire) {
      for(i <- 0 until 4) {
        for(j <- 0 until 4) {
          state(i)(j) := Tables.sbox.readAsync(state(i)(j).asUInt)
        }
      }
    }
  }

  val AddRoundKey = new Area {
    val fire = cipherState === AESState.AddRoundKey

    when(fire) {
      val addr = Vec(UInt(8 bits), 4)

      for(i <- 0 until 4) {
        addr(i) := (round * nb * 4 + i * nb).resize(8)
        state(i)(0) := state(i)(0) ^ KeyExpansion.roundKeys(addr(i) + 0)
        state(i)(1) := state(i)(1) ^ KeyExpansion.roundKeys(addr(i) + 1)
        state(i)(2) := state(i)(2) ^ KeyExpansion.roundKeys(addr(i) + 2)
        state(i)(3) := state(i)(3) ^ KeyExpansion.roundKeys(addr(i) + 3)
      }
    }
  }

  val InitStateMatrix = new Area {
    val fire = cipherState === AESState.Init

    when(fire) {
      var k = 0
      for(i <- 0 until 4) {
        for(j <- 0 until 4) {
          state(i)(j) := F.inputBlock(k)
          k = k + 1
        }
      }

      // Generate initial round keys from Key
      for (i <- 0 until 16) {
        KeyExpansion.roundKeys(i) := F.inputKey(i)
      }
    }
  }


  val Cipher = new StateMachine {
    val qIdle = new State with EntryPoint // 0
    val qInit = new State // 1
    val qKeyExpansion = new State // 2
    val qAddRoundKey = new State // 3
    val qSubBytes = new State // 4
    val qShiftRows = new State // 5
    val qMixColumns = new State // 6
    val qResp = new State // 7

    qIdle
        .whenIsActive {
            when(io.crypto.cmd.valid) {
              goto(qInit)
            }.otherwise {
              goto(qIdle)
            }
        }
    qInit
      .onEntry {
          cipherState := AESState.Init
      }
      .whenIsActive {
        goto(qKeyExpansion)
      }
    qKeyExpansion
        .onEntry {
          cipherState := AESState.KeyExpansion
          KeyExpansion.isBusy := True
        }
        .whenIsActive {
          when(!KeyExpansion.isBusy) {
            goto(qAddRoundKey)
          }.otherwise {
            goto(qKeyExpansion)
          }
        }
   qAddRoundKey
      .onEntry(cipherState := AESState.AddRoundKey)
      .whenIsActive {
        when(round === nr) {
          goto(qResp)
        }.otherwise {
          goto(qSubBytes)
        }
      }
    qSubBytes
      .onEntry(cipherState := AESState.SubBytes)
      .whenIsActive {
        goto(qShiftRows)
      }
    qShiftRows
      .onEntry(cipherState := AESState.ShiftRows)
      .whenIsActive {
        when(round === nr) {
          goto(qAddRoundKey)
        }.otherwise {
          goto(qMixColumns)
        }
      }
    qMixColumns
      .onEntry(cipherState := AESState.MixColumns)
      .whenIsActive {
        goto(qAddRoundKey)
      }
    qResp
        .onEntry(cipherState := AESState.Response)
        .whenIsActive {
          respValid := True
          goto(qIdle)
        }
  }

  // AES response signals

  io.crypto.rsp.valid := respValid
  io.crypto.rsp.block := R.responseBlock
  io.crypto.cmd.ready := respValid
}