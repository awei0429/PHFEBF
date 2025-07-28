//==================================================================================
// BSD 2-Clause License
//
// Copyright (c) 2014-2022, NJIT, Duality Technologies Inc. and other contributors
//
// All rights reserved.
//
// Author TPOC: contact@openfhe.org
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this
//    list of conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice,
//    this list of conditions and the following disclaimer in the documentation
//    and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
// FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
// DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
// CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
// OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
//==================================================================================

/*
  Example for the FHEW scheme using the default bootstrapping method (GINX)
 */

#include "binfhecontext.h"
#include<chrono>

using namespace lbcrypto;

int main() {
    // Sample Program: Step 1: Set CryptoContext

    auto cc = BinFHEContext();

    // STD128 is the security level of 128 bits of security based on LWE Estimator
    // and HE standard. Other common options are TOY, MEDIUM, STD192, and STD256.
    // MEDIUM corresponds to the level of more than 100 bits for both quantum and
    // classical computer attacks.
    cc.GenerateBinFHEContext(STD256);

    // Sample Program: Step 2: Key Generation

    // Generate the secret key
    auto start_gen = std::chrono::high_resolution_clock::now();

    auto sk = cc.KeyGen();
    auto sk2 = cc.KeyGen();
    auto sk3 = cc.KeyGen();
    auto sk4 = cc.KeyGen();
    auto sk5 = cc.KeyGen();
    auto sk6 = cc.KeyGen();
    auto sk7 = cc.KeyGen();
    auto sk8 = cc.KeyGen();
    auto sk9 = cc.KeyGen();
    auto sk10 = cc.KeyGen();

    std::cout << "Generating the bootstrapping keys..." << std::endl;

    // Generate the bootstrapping keys (refresh and switching keys)
    cc.BTKeyGen(sk);
    cc.BTKeyGen(sk2);
    cc.BTKeyGen(sk3);
    cc.BTKeyGen(sk4);
    cc.BTKeyGen(sk5);
    cc.BTKeyGen(sk6);
    cc.BTKeyGen(sk7);
    cc.BTKeyGen(sk8);
    cc.BTKeyGen(sk9);
    cc.BTKeyGen(sk10);

    std::cout << "Completed the key generation." << std::endl;

    auto end_gen = std::chrono::high_resolution_clock::now();
    auto duration_gen = std::chrono::duration_cast<std::chrono::microseconds>(end_gen - start_gen).count();
    std::cout << "Time of keygen: "<< duration_gen << " μs"<< std::endl;

    // Sample Program: Step 3: Encryption

    // Encrypt two ciphertexts representing Boolean True (1).
    // By default, freshly encrypted ciphertexts are bootstrapped.
    // If you wish to get a fresh encryption without bootstrapping, write
    // auto   ct1 = cc.Encrypt(sk, 1, LARGE_DIM);

    auto start_enc = std::chrono::high_resolution_clock::now();

    auto ct1 = cc.Encrypt(sk, 1);
    auto ct2 = cc.Encrypt(sk, 1);

    auto ct3 = cc.Encrypt(sk2, 1);
    auto ct4 = cc.Encrypt(sk2, 1);

    auto ct5 = cc.Encrypt(sk3, 1);
    auto ct6 = cc.Encrypt(sk3, 1);

    auto ct7 = cc.Encrypt(sk4, 1);
    auto ct8 = cc.Encrypt(sk4, 1);

    auto ct9 = cc.Encrypt(sk5, 1);
    auto ct10 = cc.Encrypt(sk5, 1);

    auto ct11 = cc.Encrypt(sk6, 1);
    auto ct12 = cc.Encrypt(sk6, 1);

    auto ct13 = cc.Encrypt(sk7, 1);
    auto ct14 = cc.Encrypt(sk7, 1);

    auto ct15 = cc.Encrypt(sk8, 1);
    auto ct16 = cc.Encrypt(sk8, 1);

    auto ct17 = cc.Encrypt(sk9, 1);
    auto ct18 = cc.Encrypt(sk9, 1);

    auto ct19 = cc.Encrypt(sk10, 1);
    auto ct20 = cc.Encrypt(sk10, 1);


    auto end_enc = std::chrono::high_resolution_clock::now();
    auto duration_enc = std::chrono::duration_cast<std::chrono::microseconds>(end_enc - start_enc).count();
    std::cout << "Time of Enc: "<< duration_enc << " μs"<< std::endl;

    // Sample Program: Step 4: Evaluation


    auto start_evaland = std::chrono::high_resolution_clock::now();

    // Compute (1 AND 1) = 1; Other binary gate options are OR, NAND, and NOR
    auto ctAND1 = cc.EvalBinGate(AND, ct1, ct2);

    auto ctAND2 = cc.EvalBinGate(AND, ct3, ct4);

    auto ctAND3 = cc.EvalBinGate(AND, ct5, ct6);

    auto ctAND4 = cc.EvalBinGate(AND, ct7, ct8);

    auto ctAND5 = cc.EvalBinGate(AND, ct9, ct10);

    auto ctAND6 = cc.EvalBinGate(AND, ct11, ct12);

    auto ctAND7 = cc.EvalBinGate(AND, ct13, ct14);

    auto ctAND8 = cc.EvalBinGate(AND, ct15, ct16);

    auto ctAND9 = cc.EvalBinGate(AND, ct17, ct18);

    auto ctAND10 = cc.EvalBinGate(AND, ct19, ct20);


    auto end_evaland = std::chrono::high_resolution_clock::now();
    auto duration_evaland = std::chrono::duration_cast<std::chrono::microseconds>(end_evaland - start_evaland).count();
    std::cout << "Time of Eval_And: "<< duration_evaland << " μs"<< std::endl;

    // Compute (NOT 1) = 0
    auto start_evalan = std::chrono::high_resolution_clock::now();
    //auto start_evalnot = std::chrono::high_resolution_clock::now();

    auto ct2Not = cc.EvalNOT(ct2);

    auto ct4Not = cc.EvalNOT(ct4);

    auto ct6Not = cc.EvalNOT(ct6);

    auto ct8Not = cc.EvalNOT(ct8);

    auto ct10Not = cc.EvalNOT(ct10);

    auto ct12Not = cc.EvalNOT(ct12);

    auto ct14Not = cc.EvalNOT(ct14);

    auto ct16Not = cc.EvalNOT(ct16);

    auto ct18Not = cc.EvalNOT(ct18);

    auto ct20Not = cc.EvalNOT(ct20);

    //auto end_evalnot = std::chrono::high_resolution_clock::now();
    //auto duration_evalnot = std::chrono::duration_cast<std::chrono::microseconds>(end_evalnot - start_evalnot).count();
    //std::cout << "Time of Eval_not: "<< duration_evalnot << " ms"<< std::endl;

    // Compute (1 AND (NOT 1)) = 0

    //auto start_evalan = std::chrono::high_resolution_clock::now();

    auto ctAND11 = cc.EvalBinGate(AND, ct2Not, ct1);

    auto ctAND12 = cc.EvalBinGate(AND, ct4Not, ct3);

    auto ctAND13 = cc.EvalBinGate(AND, ct6Not, ct5);

    auto ctAND14 = cc.EvalBinGate(AND, ct8Not, ct7);

    auto ctAND15 = cc.EvalBinGate(AND, ct10Not, ct9);

    auto ctAND16 = cc.EvalBinGate(AND, ct12Not, ct11);

    auto ctAND17 = cc.EvalBinGate(AND, ct14Not, ct13);

    auto ctAND18 = cc.EvalBinGate(AND, ct16Not, ct15);

    auto ctAND19 = cc.EvalBinGate(AND, ct18Not, ct17);

    auto ctAND20 = cc.EvalBinGate(AND, ct20Not, ct19);

    auto end_evalan = std::chrono::high_resolution_clock::now();
    auto duration_evalan = std::chrono::duration_cast<std::chrono::microseconds>(end_evalan - start_evalan).count();
    std::cout << "Time of Eval_andnot: "<< duration_evalan << " μs"<< std::endl;

    // Computes OR of the results in ctAND1 and ctAND2 = 1
    auto ctResult = cc.EvalBinGate(OR, ctAND1, ctAND2);

    // Sample Program: Step 5: Decryption

    auto start_dec = std::chrono::high_resolution_clock::now();

    LWEPlaintext result;

    cc.Decrypt(sk, ctResult, &result);

    auto end_dec = std::chrono::high_resolution_clock::now();
    auto duration_dec = std::chrono::duration_cast<std::chrono::microseconds>(end_dec - start_dec).count();
    std::cout << "Time of Dec: "<< duration_dec << " μs"<< std::endl;

    std::cout << "Result of encrypted computation of (1 AND 1) OR (1 AND (NOT 1)) = " << result << std::endl;

    return 0;
}
