pragma circom 2.0.0;

include "../node_modules/circomlib/circuits/poseidon.circom";
include "../node_modules/circomlib/circuits/bitify.circom";
include "../node_modules/circomlib/circuits/comparators.circom";
include "../node_modules/circomlib/circuits/sha256/sha256compression.circom";
include "../node_modules/circomlib/circuits/sha256/constants.circom";

// 248-bit chunks of a big-endian byte string, matching hash_to_field.
template PackBytes(nBytes, nChunks) {
    signal input bytes[nBytes];
    signal output packed[nChunks];

    var nBits = nBytes * 8;
    var width = 248;
    var rem = nBits % width;
    var high = rem == 0 ? width : rem;

    component bits[nBytes];
    signal stream[nBits];
    for (var i = 0; i < nBytes; i++) {
        bits[i] = Num2Bits(8);
        bits[i].in <== bytes[i];
        for (var b = 0; b < 8; b++) stream[i * 8 + b] <== bits[i].out[7 - b];
    }

    component chunkBits[nChunks];
    for (var c = 0; c < nChunks; c++) {
        var len = c == 0 ? high : width;
        var start = c == 0 ? 0 : high + (c - 1) * width;
        chunkBits[c] = Bits2Num(248);
        for (var b = 0; b < 248; b++) {
            if (b < len) chunkBits[c].in[b] <== stream[start + len - 1 - b];
            else chunkBits[c].in[b] <== 0;
        }
        packed[c] <== chunkBits[c].out;
    }
}

template BeBytesToLimbs() {
    signal input bytes[256];
    signal output limbs[64];

    for (var i = 0; i < 64; i++) {
        var base = 256 - 4 * (i + 1);
        limbs[i] <== bytes[base] * 16777216 + bytes[base + 1] * 65536 + bytes[base + 2] * 256 + bytes[base + 3];
    }
}

// 64 little-endian 32-bit limbs. a * b = q * n + r and r < n.
template ModMul() {
    signal input a[64];
    signal input b[64];
    signal input n[64];
    signal input q[64];
    signal input r[64];
    signal input borrow[65];

    component aBits[64];
    component bBits[64];
    component nBits[64];
    component qBits[64];
    component rBits[64];
    signal products[64][64];
    for (var i = 0; i < 64; i++) {
        aBits[i] = Num2Bits(32);
        bBits[i] = Num2Bits(32);
        nBits[i] = Num2Bits(32);
        qBits[i] = Num2Bits(32);
        rBits[i] = Num2Bits(32);
        aBits[i].in <== a[i];
        bBits[i].in <== b[i];
        nBits[i].in <== n[i];
        qBits[i].in <== q[i];
        rBits[i].in <== r[i];
        for (var j = 0; j < 64; j++) products[i][j] <== a[i] * b[j];
    }

    signal abTerm[128][64];
    signal abAcc[128][65];
    signal qnTerm[128][64];
    signal qnAcc[128][65];
    signal qnProducts[64][64];
    for (var i = 0; i < 64; i++) {
        for (var j = 0; j < 64; j++) qnProducts[i][j] <== q[i] * n[j];
    }
    for (var k = 0; k < 128; k++) {
        var start = k > 63 ? k - 63 : 0;
        var end = k < 63 ? k : 63;
        abAcc[k][0] <== 0;
        qnAcc[k][0] <== 0;
        for (var t = 0; t < 64; t++) {
            var idx = start + t;
            if (idx <= end) {
                abTerm[k][t] <== products[idx][k - idx];
                qnTerm[k][t] <== qnProducts[idx][k - idx];
            } else {
                abTerm[k][t] <== 0;
                qnTerm[k][t] <== 0;
            }
            abAcc[k][t + 1] <== abAcc[k][t] + abTerm[k][t];
            qnAcc[k][t + 1] <== qnAcc[k][t] + qnTerm[k][t];
        }
    }

    signal abCarry[129];
    signal qnCarry[129];
    signal abLimbs[128];
    signal qnLimbs[128];
    abCarry[0] <== 0;
    qnCarry[0] <== 0;
    component abSplit[128];
    component qnSplit[128];
    component abLow[128];
    component qnLow[128];
    component abHigh[128];
    component qnHigh[128];
    for (var k = 0; k < 128; k++) {
        abSplit[k] = Num2Bits(80);
        qnSplit[k] = Num2Bits(80);
        abSplit[k].in <== abAcc[k][64] + abCarry[k];
        qnSplit[k].in <== qnAcc[k][64] + qnCarry[k];
        abLow[k] = Bits2Num(32);
        qnLow[k] = Bits2Num(32);
        abHigh[k] = Bits2Num(48);
        qnHigh[k] = Bits2Num(48);
        for (var bit = 0; bit < 32; bit++) {
            abLow[k].in[bit] <== abSplit[k].out[bit];
            qnLow[k].in[bit] <== qnSplit[k].out[bit];
        }
        for (var bit = 0; bit < 48; bit++) {
            abHigh[k].in[bit] <== abSplit[k].out[32 + bit];
            qnHigh[k].in[bit] <== qnSplit[k].out[32 + bit];
        }
        abLimbs[k] <== abLow[k].out;
        qnLimbs[k] <== qnLow[k].out;
        abCarry[k + 1] <== abHigh[k].out;
        qnCarry[k + 1] <== qnHigh[k].out;
    }
    abCarry[128] === 0;
    qnCarry[128] === 0;

    signal rPad[128];
    signal sumCarry[129];
    signal sumLimb[128];
    sumCarry[0] <== 0;
    component sumSplit[128];
    component sumLow[128];
    for (var k = 0; k < 128; k++) {
        if (k < 64) rPad[k] <== r[k];
        else rPad[k] <== 0;
        sumSplit[k] = Num2Bits(34);
        sumSplit[k].in <== qnLimbs[k] + rPad[k] + sumCarry[k];
        sumLow[k] = Bits2Num(32);
        for (var bit = 0; bit < 32; bit++) sumLow[k].in[bit] <== sumSplit[k].out[bit];
        sumLimb[k] <== sumLow[k].out;
        sumCarry[k + 1] <== sumSplit[k].out[32] + 2 * sumSplit[k].out[33];
        sumLimb[k] === abLimbs[k];
    }
    sumCarry[128] === 0;

    borrow[0] === 0;
    borrow[64] === 0;
    signal adjusted[64];
    signal seen[65];
    seen[0] <== 0;
    component borrowBit[65];
    component adjustedBits[64];
    component zero[64];
    for (var i = 0; i < 65; i++) {
        borrowBit[i] = Num2Bits(1);
        borrowBit[i].in <== borrow[i];
    }
    for (var i = 0; i < 64; i++) {
        adjusted[i] <== n[i] + borrow[i + 1] * 4294967296 - r[i] - borrow[i];
        adjustedBits[i] = Num2Bits(32);
        adjustedBits[i].in <== adjusted[i];
        zero[i] = IsZero();
        zero[i].in <== adjusted[i];
        seen[i + 1] <== seen[i] + (1 - zero[i].out);
    }
    component same = IsZero();
    same.in <== seen[64];
    same.out === 0;
}

template ZkLoginMYSO() {
    var MAX_MSG = 1408;
    var NBLOCKS = 23;
    var PAD = 1472;
    var ISS_SCAN = 64;
    var ISS_PAD = 224;
    var HEADER = 248;

    signal input eph0;
    signal input eph1;
    signal input addrSeed;
    signal input maxEpoch;
    signal input indexMod4;
    signal input messageLen;
    signal input headerLen;
    signal input issOffset;
    signal input issQuot;
    signal input issLen;
    signal input nBlocks;
    signal input padRem;
    signal input messageBytes[MAX_MSG];
    signal input modulusBytes[256];
    signal input signatureBytes[256];
    signal input sigBorrow[65];
    signal input squareQ[16][64];
    signal input squareR[16][64];
    signal input squareBorrow[16][65];
    signal input finalQ[64];
    signal input finalR[64];
    signal input finalBorrow[65];
    signal output publicHash;

    component eph0Bits = Num2Bits(136);
    component eph1Bits = Num2Bits(128);
    component epochBits = Num2Bits(64);
    eph0Bits.in <== eph0;
    eph1Bits.in <== eph1;
    epochBits.in <== maxEpoch;

    component msgFit = LessThan(11);
    msgFit.in[0] <== messageLen;
    msgFit.in[1] <== MAX_MSG + 1;
    msgFit.out === 1;
    component headerFit = LessThan(9);
    headerFit.in[0] <== headerLen;
    headerFit.in[1] <== HEADER + 1;
    headerFit.out === 1;
    component headerInside = LessThan(12);
    headerInside.in[0] <== headerLen;
    headerInside.in[1] <== messageLen;
    headerInside.out === 1;
    component issFit = LessThan(8);
    issFit.in[0] <== issLen;
    issFit.in[1] <== ISS_SCAN + 1;
    issFit.out === 1;
    component offsetFit = LessThan(11);
    offsetFit.in[0] <== issOffset;
    offsetFit.in[1] <== MAX_MSG;
    offsetFit.out === 1;

    component quotBits = Num2Bits(11);
    quotBits.in <== issQuot;
    indexMod4 === issOffset - issQuot * 4;
    component indexFit = LessThan(3);
    indexFit.in[0] <== indexMod4;
    indexFit.in[1] <== 4;
    indexFit.out === 1;

    component msgBits[MAX_MSG];
    component msgPast[MAX_MSG];
    for (var i = 0; i < MAX_MSG; i++) {
        msgBits[i] = Num2Bits(8);
        msgBits[i].in <== messageBytes[i];
        msgPast[i] = LessThan(12);
        msgPast[i].in[0] <== messageLen;
        msgPast[i].in[1] <== i + 1;
        messageBytes[i] * msgPast[i].out === 0;
    }

    signal issStart;
    issStart <== headerLen + 1 + issOffset;
    component sliceFit = LessEqThan(12);
    sliceFit.in[0] <== issStart + issLen;
    sliceFit.in[1] <== messageLen;
    sliceFit.out === 1;

    signal headerBytes[HEADER];
    component headerLive[HEADER];
    for (var i = 0; i < HEADER; i++) {
        headerLive[i] = LessThan(9);
        headerLive[i].in[0] <== i;
        headerLive[i].in[1] <== headerLen;
        headerBytes[i] <== headerLive[i].out * messageBytes[i];
    }

    signal dotAcc[MAX_MSG + 1];
    component dotEq[MAX_MSG];
    dotAcc[0] <== 0;
    for (var i = 0; i < MAX_MSG; i++) {
        dotEq[i] = IsEqual();
        dotEq[i].in[0] <== headerLen;
        dotEq[i].in[1] <== i;
        dotAcc[i + 1] <== dotAcc[i] + dotEq[i].out * messageBytes[i];
    }
    dotAcc[MAX_MSG] === 46;

    signal issBytes[ISS_PAD];
    component issLive[ISS_SCAN];
    component issEq[ISS_SCAN][MAX_MSG];
    signal issAcc[ISS_SCAN][MAX_MSG + 1];
    for (var i = 0; i < ISS_SCAN; i++) {
        issLive[i] = LessThan(8);
        issLive[i].in[0] <== i;
        issLive[i].in[1] <== issLen;
        issAcc[i][0] <== 0;
        for (var j = 0; j < MAX_MSG; j++) {
            issEq[i][j] = IsEqual();
            issEq[i][j].in[0] <== issStart + i;
            issEq[i][j].in[1] <== j;
            issAcc[i][j + 1] <== issAcc[i][j] + issEq[i][j].out * messageBytes[j];
        }
        issBytes[i] <== issLive[i].out * issAcc[i][MAX_MSG];
    }
    for (var i = ISS_SCAN; i < ISS_PAD; i++) issBytes[i] <== 0;

    component issPack = PackBytes(ISS_PAD, 8);
    component headerPack = PackBytes(HEADER, 8);
    component modulusPack = PackBytes(256, 9);
    for (var i = 0; i < ISS_PAD; i++) issPack.bytes[i] <== issBytes[i];
    for (var i = 0; i < HEADER; i++) headerPack.bytes[i] <== headerBytes[i];
    for (var i = 0; i < 256; i++) modulusPack.bytes[i] <== modulusBytes[i];

    signal paddedLen;
    paddedLen <== nBlocks * 64;
    component blockFit = LessThan(6);
    blockFit.in[0] <== nBlocks;
    blockFit.in[1] <== NBLOCKS + 1;
    blockFit.out === 1;
    component blockZero = IsZero();
    blockZero.in <== nBlocks;
    blockZero.out === 0;
    component remFit = LessThan(10);
    remFit.in[0] <== padRem;
    remFit.in[1] <== 512;
    remFit.out === 1;
    messageLen * 8 + 64 === (nBlocks - 1) * 512 + padRem;

    component bitlen = Num2Bits(32);
    bitlen.in <== messageLen * 8;
    signal lengthBytes[8];
    lengthBytes[0] <== 0;
    lengthBytes[1] <== 0;
    lengthBytes[2] <== 0;
    lengthBytes[3] <== 0;
    component lengthChunk[4];
    for (var w = 0; w < 4; w++) {
        lengthChunk[w] = Bits2Num(8);
        for (var b = 0; b < 8; b++) lengthChunk[w].in[b] <== bitlen.out[(3 - w) * 8 + b];
        lengthBytes[4 + w] <== lengthChunk[w].out;
    }

    component isContent[PAD];
    component isMarker[PAD];
    component isUnused[PAD];
    component lenFrom[PAD];
    component lenTo[PAD];
    component lenAt[PAD][8];
    signal lenPick[PAD][9];
    signal isLength[PAD];
    signal isZeroPad[PAD];
    signal padded[PAD];
    signal markerPart[PAD];
    signal lenPart[PAD];
    signal contentPart[PAD];
    for (var i = 0; i < PAD; i++) {
        isContent[i] = LessThan(12);
        isContent[i].in[0] <== i;
        isContent[i].in[1] <== messageLen;
        isMarker[i] = IsEqual();
        isMarker[i].in[0] <== i;
        isMarker[i].in[1] <== messageLen;
        isUnused[i] = LessThan(12);
        isUnused[i].in[0] <== paddedLen;
        isUnused[i].in[1] <== i + 1;
        lenFrom[i] = LessEqThan(12);
        lenFrom[i].in[0] <== paddedLen - 8;
        lenFrom[i].in[1] <== i;
        lenTo[i] = LessThan(12);
        lenTo[i].in[0] <== i;
        lenTo[i].in[1] <== paddedLen;
        isLength[i] <== lenFrom[i].out * lenTo[i].out;
        isZeroPad[i] <== 1 - isContent[i].out - isMarker[i].out - isUnused[i].out - isLength[i];
        isZeroPad[i] * (isZeroPad[i] - 1) === 0;
        lenPick[i][0] <== 0;
        for (var t = 0; t < 8; t++) {
            lenAt[i][t] = IsEqual();
            lenAt[i][t].in[0] <== i;
            lenAt[i][t].in[1] <== paddedLen - 8 + t;
            lenPick[i][t + 1] <== lenPick[i][t] + lenAt[i][t].out * lengthBytes[t];
        }
        markerPart[i] <== isMarker[i].out * 128;
        lenPart[i] <== isLength[i] * lenPick[i][8];
        if (i < MAX_MSG) {
            contentPart[i] <== isContent[i].out * messageBytes[i];
        } else {
            contentPart[i] <== 0;
        }
        padded[i] <== contentPart[i] + markerPart[i] + lenPart[i];
    }

    component padBits[PAD];
    signal stream[PAD * 8];
    for (var i = 0; i < PAD; i++) {
        padBits[i] = Num2Bits(8);
        padBits[i].in <== padded[i];
        for (var b = 0; b < 8; b++) stream[i * 8 + b] <== padBits[i].out[7 - b];
    }

    component iv[8];
    for (var w = 0; w < 8; w++) iv[w] = H(w);
    component hasher[NBLOCKS];
    for (var block = 0; block < NBLOCKS; block++) {
        hasher[block] = Sha256compression();
        if (block == 0) {
            for (var w = 0; w < 8; w++) {
                for (var k = 0; k < 32; k++) hasher[block].hin[w * 32 + k] <== iv[w].out[k];
            }
        } else {
            for (var w = 0; w < 8; w++) {
                for (var k = 0; k < 32; k++) hasher[block].hin[w * 32 + k] <== hasher[block - 1].out[w * 32 + 31 - k];
            }
        }
        for (var k = 0; k < 512; k++) hasher[block].inp[k] <== stream[block * 512 + k];
    }

    component which[NBLOCKS];
    signal hashAcc[NBLOCKS + 1][256];
    for (var b = 0; b < 256; b++) hashAcc[0][b] <== 0;
    for (var block = 0; block < NBLOCKS; block++) {
        which[block] = IsEqual();
        which[block].in[0] <== nBlocks;
        which[block].in[1] <== block + 1;
        for (var b = 0; b < 256; b++) {
            hashAcc[block + 1][b] <== hashAcc[block][b] + which[block].out * hasher[block].out[b];
        }
    }
    component hashByte[32];
    for (var i = 0; i < 32; i++) {
        hashByte[i] = Bits2Num(8);
        for (var b = 0; b < 8; b++) hashByte[i].in[b] <== hashAcc[NBLOCKS][i * 8 + 7 - b];
    }

    signal em[256];
    em[0] <== 0;
    em[1] <== 1;
    for (var i = 2; i < 204; i++) em[i] <== 255;
    em[204] <== 0;
    var digestInfo[19] = [48, 49, 48, 13, 6, 9, 96, 134, 72, 1, 101, 3, 4, 2, 1, 5, 0, 4, 32];
    for (var i = 0; i < 19; i++) em[205 + i] <== digestInfo[i];
    for (var i = 0; i < 32; i++) em[224 + i] <== hashByte[i].out;

    component modLimbs = BeBytesToLimbs();
    component sigLimbs = BeBytesToLimbs();
    component emLimbs = BeBytesToLimbs();
    for (var i = 0; i < 256; i++) {
        modLimbs.bytes[i] <== modulusBytes[i];
        sigLimbs.bytes[i] <== signatureBytes[i];
        emLimbs.bytes[i] <== em[i];
    }

    signal sigAdjusted[64];
    signal sigSeen[65];
    sigBorrow[0] === 0;
    sigBorrow[64] === 0;
    sigSeen[0] <== 0;
    component sigBorrowBit[65];
    component sigAdjustedBits[64];
    component sigZero[64];
    for (var i = 0; i < 65; i++) {
        sigBorrowBit[i] = Num2Bits(1);
        sigBorrowBit[i].in <== sigBorrow[i];
    }
    for (var i = 0; i < 64; i++) {
        sigAdjusted[i] <== modLimbs.limbs[i] + sigBorrow[i + 1] * 4294967296 - sigLimbs.limbs[i] - sigBorrow[i];
        sigAdjustedBits[i] = Num2Bits(32);
        sigAdjustedBits[i].in <== sigAdjusted[i];
        sigZero[i] = IsZero();
        sigZero[i].in <== sigAdjusted[i];
        sigSeen[i + 1] <== sigSeen[i] + (1 - sigZero[i].out);
    }
    component sigSame = IsZero();
    sigSame.in <== sigSeen[64];
    sigSame.out === 0;

    component square[16];
    signal round[17][64];
    for (var i = 0; i < 64; i++) round[0][i] <== sigLimbs.limbs[i];
    for (var s = 0; s < 16; s++) {
        square[s] = ModMul();
        for (var i = 0; i < 64; i++) {
            square[s].a[i] <== round[s][i];
            square[s].b[i] <== round[s][i];
            square[s].n[i] <== modLimbs.limbs[i];
            square[s].q[i] <== squareQ[s][i];
            square[s].r[i] <== squareR[s][i];
            round[s + 1][i] <== squareR[s][i];
        }
        for (var i = 0; i < 65; i++) square[s].borrow[i] <== squareBorrow[s][i];
    }

    component finalMul = ModMul();
    for (var i = 0; i < 64; i++) {
        finalMul.a[i] <== round[16][i];
        finalMul.b[i] <== round[0][i];
        finalMul.n[i] <== modLimbs.limbs[i];
        finalMul.q[i] <== finalQ[i];
        finalMul.r[i] <== finalR[i];
        finalR[i] === emLimbs.limbs[i];
    }
    for (var i = 0; i < 65; i++) finalMul.borrow[i] <== finalBorrow[i];

    component issHash = Poseidon(8);
    component headerHash = Poseidon(8);
    component modulusHash = Poseidon(9);
    component all = Poseidon(8);
    for (var i = 0; i < 8; i++) {
        issHash.inputs[i] <== issPack.packed[i];
        headerHash.inputs[i] <== headerPack.packed[i];
    }
    for (var i = 0; i < 9; i++) modulusHash.inputs[i] <== modulusPack.packed[i];
    all.inputs[0] <== eph0;
    all.inputs[1] <== eph1;
    all.inputs[2] <== addrSeed;
    all.inputs[3] <== maxEpoch;
    all.inputs[4] <== issHash.out;
    all.inputs[5] <== indexMod4;
    all.inputs[6] <== headerHash.out;
    all.inputs[7] <== modulusHash.out;
    publicHash <== all.out;
}

component main = ZkLoginMYSO();
