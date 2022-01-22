const { MerkleTree } = require('merkletreejs')
const SHA256 = require('crypto-js/sha256')
const { hash, number} = require("starknet")
const { SnarkMerkleTree , getProof, checkProof,checkProofOrdered} = require("./snarkmerkle")
const leaves = ['a', 'b', 'c'].map(x => SHA256(x))
const leaves2 = [1,2,3,4,5,6,7,8,9,10,11,12];//.map(x=>hash.pedersen([0,number.toBN(x)]))
console.log(leaves2)
const tree = new MerkleTree(leaves, SHA256)

const elements = [1, 2,3,4,5,6,7,8,9,10,11].map(x=>hash.pedersen([0,x]));
console.log(elements);

const smt = new SnarkMerkleTree(elements,true);

console.log("smt root:",smt.getRoot());
const proof1 = smt.getProofOrdered(elements[2],3);
console.log("proof1:",proof1);
console.log("check proof ordered:",checkProofOrdered(proof1, smt.getRoot(), elements[2], 3));
const proof2 = smt.getProofOrdered(elements[4],5);
console.log("proof2:",proof2);
console.log("check proof ordered high element:",checkProofOrdered(proof2, smt.getRoot(), elements[4], 5));

const proof3 = smt.getProofOrdered(elements[8],9);
console.log("proof3 (convert to felt):",proof3);
console.log("check proof ordered high element:",checkProofOrdered(proof3, smt.getRoot(), elements[8], 9));
//console.log("check proof:",checkProof(proof1, smt.getRoot(), elements[2]));
console.log("root:",smt.getRoot());
const root = tree.getRoot().toString('hex')
const leaf = SHA256('a')
const proof = tree.getProof(leaf)
console.log(tree.verify(proof, leaf, root)) // true
console.log(hash.pedersen)
const badLeaves = ['a', 'x', 'c'].map(x => SHA256(x))
const badTree = new MerkleTree(badLeaves, SHA256)
const badLeaf = SHA256('x')
const badProof = tree.getProof(badLeaf)
console.log(tree.verify(badProof, leaf, root)) // false
