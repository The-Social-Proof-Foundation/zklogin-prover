pragma circom 2.0.0;

include "../node_modules/circomlib/circuits/poseidon.circom";
include "../node_modules/circomlib/circuits/comparators.circom";

template ZkLoginMys() {
    signal input jwtHash;
    signal input nonce;
    signal input pubKeyHash;
    signal output isValid;

    component poseidon = Poseidon(2);
    poseidon.inputs[0] <== nonce;
    poseidon.inputs[1] <== pubKeyHash;

    component eq = IsEqual();
    eq.in[0] <== jwtHash;
    eq.in[1] <== poseidon.out;
    isValid <== eq.out;
}

component main = ZkLoginMys(); 