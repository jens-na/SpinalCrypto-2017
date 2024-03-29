/*                                                                           *\
**        _____ ____  _____   _____    __                                    **
**       / ___// __ \/  _/ | / /   |  / /   Crypto                           **
**       \__ \/ /_/ // //  |/ / /| | / /    (c) Dolu, All rights reserved    **
**      ___/ / ____// // /|  / ___ |/ /___                                   **
**     /____/_/   /___/_/ |_/_/  |_/_____/                                   **
**                                                                           **
**      This library is free software; you can redistribute it and/or        **
**    modify it under the terms of the GNU Lesser General Public             **
**    License as published by the Free Software Foundation; either           **
**    version 3.0 of the License, or (at your option) any later version.     **
**                                                                           **
**      This library is distributed in the hope that it will be useful,      **
**    but WITHOUT ANY WARRANTY; without even the implied warranty of         **
**    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU      **
**    Lesser General Public License for more details.                        **
**                                                                           **
**      You should have received a copy of the GNU Lesser General Public     **
**    License along with this library.                                       **
\*                                                                           */
package spinalcrypto.hash.md5

import spinal.core._
import scala.math.{pow, sin}


/**
  * MD5Core Specification
  */
object MD5CoreSpec{

  /** Size of a message block */
  def blockWidth    = 512 bits
  /** Size of the A B C D block */
  def subBlockWidth =  32 bits
  /** Digest message */
  def hashWidth     = 128 bits
  /** Total number of iterations */
  def nbrIteration  = 4*16
  /** Width of the counter of bit */
  def cntBitWidth   = 64 bits


  def initBlockA = B"x67452301"
  def initBlockB = B"xEFCDAB89"
  def initBlockC = B"x98BADCFE"
  def initBlockD = B"x10325476"


  def funcF(b: Bits, c: Bits, d: Bits): Bits = (b & c) | (~b & d)
  def funcG(b: Bits, c: Bits, d: Bits): Bits = (b & d) | (~d & c)
  def funcH(b: Bits, c: Bits, d: Bits): Bits = b ^ c ^ d
  def funcI(b: Bits, c: Bits, d: Bits): Bits = c ^ (b | ~d)


  /** T[i] := floor(2^32 × abs(sin(i + 1))) */
  def constantT: List[BigInt] = for(i <- List.range(0,64)) yield BigDecimal((pow(2,32) * sin(i + 1.0).abs)).toBigInt()


  /**
    * ShiftValue is used to know how much left rotation must be done
    * Original array :
    *   7, 12, 17, 22,  7, 12, 17, 22,  7, 12, 17, 22,  7, 12, 17, 22,
    *   5,  9, 14, 20,  5,  9, 14, 20,  5,  9, 14, 20,  5,  9, 14, 20,
    *   4, 11, 16, 23,  4, 11, 16, 23,  4, 11, 16, 23,  4, 11, 16, 23,
    *   6, 10, 15, 21,  6, 10, 15, 21,  6, 10, 15, 21,  6, 10, 15, 21)
    */
  def shiftCstS: List[Int] = List(7, 12, 17, 22, 5, 9, 14, 20, 4, 11, 16, 23, 6, 10, 15, 21)


  /**
    * Index K is used to select a word in the 512-bit of the message block
    *  0 .. 15 : index = i
    * 16 .. 31 : index = 5 * i + 1 mod 16
    * 32 .. 47 : index = 3 * i + 5 mod 16
    * 63 .. 34 : index = 7 * i mod 16
    */
  def indexK: List[Int] = for(i <- List.range(0, 64)) yield if      (i < 16) i
                                                            else if (i < 32) (5 * i + 1) % 16
                                                            else if (i < 48) (3 * i + 5) % 16
                                                            else             (7 * i) % 16
}
