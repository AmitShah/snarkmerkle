# [StarkNet](https://starkware.co/product/starknet/) is a permissionless decentralized ZK-Rollup operating
# as an L2 network over Ethereum, where any dApp can achieve
# unlimited scale for its computation, without compromising
# Ethereum's composability and security.
#
# This is a simple StarkNet contract.
# Note that you won't be able to use the playground to compile and run it,
# but you can deploy it on the [StarkNet Planets Alpha network](https://medium.com/starkware/starknet-planets-alpha-on-ropsten-e7494929cb95)!
#
# 1. Click on "Deploy" to deploy the contract.
#    For more information on how to write Cairo contracts see the
#    ["Hello StarkNet" tutorial](https://cairo-lang.org/docs/hello_starknet).
# 2. Click on the contract address in the output pane to open
#    [Voyager](https://voyager.online/) - the StarkNet block explorer.
# 3. Wait for the page to load the information
#    (it may take a few minutes until a block is created).
# 4. In the "STATE" tab, you can call the "add()" transaction.

# The "%lang" directive declares this code as a StarkNet contract.
%lang starknet

# Dynamic allocation in Cairo is done using the `alloc` function,
# which itself is implemented in Cairo using the
# [segments](https://www.cairo-lang.org/docs/how_cairo_works/segments.html) mechanism.
# Thanks to this mechanism, `alloc` allocates an array of an arbitrary size,
# which does not need to be specified in the call.
#
# The function `sqr_array` should compute and return an array
# of the square values of a given array.
# Write the body of `sqr_array` using the given helper function
# `_inner_sqr_array` and check that the program output
# is 1, 4, 9, 16.
# `sqr_array` should allocate the new array it returns.

# Use the output builtin.
%builtins pedersen range_check bitwise

from starkware.cairo.common.cairo_builtins import HashBuiltin
from starkware.cairo.common.cairo_builtins import BitwiseBuiltin
from starkware.cairo.common.alloc import alloc
from starkware.cairo.common.serialize import serialize_word
from starkware.cairo.common.hash import hash2
from starkware.cairo.common.math import assert_nn_le,unsigned_div_rem,assert_lt,assert_nn
from starkware.cairo.common.bitwise import bitwise_and, bitwise_xor
from starkware.cairo.common.math_cmp import is_nn,is_le
from starkware.cairo.common.hash import hash2
from starkware.cairo.common.signature import (
    verify_ecdsa_signature)
from starkware.starknet.common.syscalls import get_tx_signature
from starkware.starknet.common.syscalls import get_caller_address

@storage_var
func Ownable_owner() -> (owner: felt):
end

# Fills `new_array` with the squares of the first `length` elements in `array`.
func _inner_sqr_array(array : felt*, new_array : felt*, length : felt):
    if length == 0:
        return ()
    end

    assert [new_array] = [array] * [array]

    _inner_sqr_array(array=array + 1, new_array=new_array + 1, length=length - 1)
    return ()
end

func sqr_array(array : felt*, length : felt) -> (new_array : felt*):
    alloc_locals
    let (local _new_array)= alloc()
    _inner_sqr_array(array,_new_array,length)
    
    return(_new_array)
    # Write your code here.
end

#this function is only useful for larger exponents 2^x where x > 20
func fast_two_pow{bitwise_ptr : BitwiseBuiltin*}(a:felt,n:felt)->(result):
    alloc_locals
    if n==0:
      return (1)
    end
    if n == 1:
        return (a)
    end
    let ( local odd) = bitwise_and{bitwise_ptr=bitwise_ptr}(n,0x1) 
    let (x)=fast_two_pow(a,(n-odd)/2)
    let x2=x*x
    
    if odd == 1:
      let xa =x2*a
      return (xa)
    end
    return (x2)
end
    
func two_pow(exp) -> (result):
    if exp == 0:
        return (1)
    end
    let (two_pow_n_minus_1) = two_pow(exp -1)
    return (2 * two_pow_n_minus_1)
end

func layer_index{range_check_ptr,bitwise_ptr : BitwiseBuiltin*}(proof_len:felt, i:felt, index:felt)->(new_index):
     #  while (remaining && index % 2 === 1 && index > Math.pow(2, remaining)) {
  #    index = Math.round(index / 2)
  #  }
    alloc_locals
    tempvar remaining = proof_len - i    
    let (local odd) = bitwise_and{bitwise_ptr=bitwise_ptr}(index,0x1)     
    let (local pow2) = two_pow(remaining)
    let (local isle) = is_le(pow2,index-1) 
    #assert_nn(odd)
    #assert_nn(remaining)
    if remaining !=0 :
        if odd == 1 :
           if  isle== 1:
                return layer_index(proof_len, i, (index+odd)/2)
            end
                #return (new_index=index/2
        end
   end
    return(index)
    #return(new_index=index)
end

func _checkProofOrdered{range_check_ptr,bitwise_ptr : BitwiseBuiltin*,pedersen_ptr : HashBuiltin*}(proof_len: felt, proof:felt *, index:felt, i:felt, accum:felt*)->(rootHash):
    alloc_locals
    if i == proof_len:
        return([accum+i])
    end
    
    let (local new_index) = layer_index(proof_len, i, index)
    let (local odd) =  bitwise_and{bitwise_ptr=bitwise_ptr}(new_index,0x1)     
    if odd == 0:
        let (h_element) = hash2{hash_ptr=pedersen_ptr}(
            [proof+i], [accum+i]
        )
        assert [accum+i+1] = h_element
    else:
         let (h_element) = hash2{hash_ptr=pedersen_ptr}(
            [accum+i], [proof+i]
        )
        
        assert [accum+i+1] = h_element
    end
  #    tempHash = combinedHash(proof[i], tempHash, true)
  #  } else {
  #    tempHash = combinedHash(tempHash, proof[i], true)
  #  }
  #  index = Math.round(index / 2)
    
    let new_new_index = (new_index+odd)/2 
    return _checkProofOrdered(proof_len, proof,new_new_index,i+1,accum)
end

func checkProofOrdered{range_check_ptr, bitwise_ptr : BitwiseBuiltin*, pedersen_ptr : HashBuiltin*}(proof_len: felt, proof:felt *, element:felt, index:felt)->(result):
  alloc_locals
  let (local proofHash) = alloc()
  let (h_element) = hash2{hash_ptr=pedersen_ptr}(
        0, element
    )

  assert [proofHash] = h_element #set to the 0th element to the pedersen_hash of 
  
  return _checkProofOrdered(proof_len=proof_len, proof=proof,index=index,i=0,accum=proofHash)
  #for (let i = 0; i < proof.length; i++) {
  #  let remaining = proof.length - i

 

  #  if (index % 2 === 0) {
  #    tempHash = combinedHash(proof[i], tempHash, true)
  #  } else {
  #    tempHash = combinedHash(tempHash, proof[i], true)
  #  }
  #  index = Math.round(index / 2)
  #}
  #return()
end



@external
func claimXp{pedersen_ptr : HashBuiltin*,range_check_ptr,bitwise_ptr : BitwiseBuiltin*,ecdsa_ptr : SignatureBuiltin* }(root: felt,sig : (felt, felt), proof_len:felt, proof:felt *, element:felt, index:felt)->(res: felt){
   //let (amount_hash) = hash2{hash_ptr=pedersen_ptr}( 0,root)
   //get owner from smartcontract storage
  let (owner) = Ownable_owner.read()
  verify_ecdsa_signature(
        message=root,
        public_key=owner,
        signature_r=sig[0],
        signature_s=sig[1])
  return (owner)

}

func Ownable_initializer{
        syscall_ptr : felt*, 
        pedersen_ptr : HashBuiltin*,
        range_check_ptr
    }(owner: felt):
    Ownable_owner.write(owner)
    return ()
end

@constructor
func constructor{
        syscall_ptr : felt*, 
        pedersen_ptr : HashBuiltin*,
        range_check_ptr
    }():
    let address = get_caller_address()
    Ownable_initializer(address)
    return ()
end

@view
func checkProof{pedersen_ptr : HashBuiltin*,range_check_ptr,bitwise_ptr : BitwiseBuiltin* }()->(res: felt):
    alloc_locals
    # Allocate a new array.
    let (local array) = alloc()
    # Fill the new array with field elements.
    assert [array] = 1
    assert [array + 1] = 2
    assert [array + 2] = 3
    assert [array + 3] = 4
    
    let (new_index) = layer_index(1, 0,5)
    let (new_index2) = layer_index(3, 0,3)
    let (new_array) = sqr_array(array=array, length=4)
    #serialize_word([new_array])
    #serialize_word([new_array + 1])
    #serialize_word([new_array + 2])
    #serialize_word([new_array + 3])
    #serialize_word(new_index)
    #serialize_word(new_index2)
    
    let ( local proof) = alloc()
    assert [proof] = 458933264452572171106695256465341160654132084710250671055261382009315664425
    assert [proof +1] = 3039549616176004825304846612582934807352022669398633945270433454544202693289
    assert [proof + 2] = 3344223123784052057366048933846905716067140384361791026153972616805110454637
    let (result) = checkProofOrdered(3, proof, 3, 3)
    assert result = 3002914030709981785394142290262415585126925225590645014594462327270019158819
    let ( local proof2) = alloc()
    assert [proof2] = 1770601910604849239015390784294547573224852814384385895400605469146907098352
    let (result2) = checkProofOrdered(1, proof2, 5, 5)
    assert result2 = 3002914030709981785394142290262415585126925225590645014594462327270019158819
    let (ftp) = fast_two_pow(2,24)
    #let(ftp) = two_pow(24)
    #serialize_word(ftp)
    return (result2)
end

