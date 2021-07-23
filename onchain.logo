type storage is string

type parameter is
  StoreMessage of string

type return is list (operation) * storage

function storeInSC (const store : storage; const name : string) : storage is 
block{
  var returnname: string := "";
  const signed : signature = ("spsig1JcEvjoXgsi3e7eiemSJiPwSioi7NGKST1vJKs6qLRiN5BGzPyBbwcgqr5PxQrrtdFdK4kxYdTe4zWyB6S8AoasrnsQhpC": signature);
 
  var namebyte: bytes := Bytes.pack(name);
  const pubKey : key = ("sppk7a5nkoBr4TjX8yzcpRTBF88sfQWhKM1Ec5H3XT9VYjVyTin9zvy":key);
   
    if(Crypto.check(pubKey, signed, Crypto.sha256(namebyte))) then {
        returnname := name;
    } else {
        returnname := store;
    }
} with returnname

function main (const action : parameter; const store : storage) : return is
 ((nil : list (operation)),    // No operations
  case action of
     StoreMessage (n) -> storeInSC (store, n)
  end)

