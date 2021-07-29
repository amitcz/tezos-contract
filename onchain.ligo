type storage is record [
  publicKey  : key;
  message  : string
]

type parameter is
  StoreMessage of (string * bytes * signature) 
| StorePublic of key                     

type return is list (operation) * storage


// Public key will be stored in advance
function storePublic (const _publicKey : key; const store : storage) : storage is 
  record[publicKey = _publicKey; message = store.message]


// Will receive msg, msgHex  and signature for verification purpose
function storeInSC (const store : storage; const origMsg : string; const hexMsg : bytes; const spsig : signature) : storage is 
 block {

  var returnname :=
      record [
        publicKey  = store.publicKey;
        message  = store.message
      ];
 
  var namehashbytes: bytes := hexMsg;

  var hashed: bytes := Crypto.sha256(namehashbytes);

   
    if(Crypto.check(store.publicKey, spsig, hashed)) then {
        returnname :=
      record [
        publicKey  = store.publicKey;
        message  = origMsg
      ];
    } else {
        // returnname := name;
        returnname :=
      record [
        publicKey  = store.publicKey;
        message  = store.message
      ];
    }
} with returnname

function main (const action : parameter; const store : storage) : return is
 ((nil : list (operation)),    // No operations
  case action of
     StoreMessage (origMsg, hexMsg, spsig) -> storeInSC (store, origMsg, hexMsg, spsig)  // message verification
    |StorePublic (key) -> storePublic (key, store)       // public key
  end)
