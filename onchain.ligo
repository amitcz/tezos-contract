type storage is record [
  publicKey  : key;
  message  : string;
  checkTx : bool; 
]
type parameter is
   StorePublic of (key * signature)  
 | StoreMessage of (string * signature)                    
type return is list (operation) * storage


function storePublic (const publicKey : key; const spsig : signature;  const store : storage) : storage is 
 block {

    var hexOptimisedPublicKey : bytes := Bytes.pack(publicKey);

    var firstReturn :=  
            record [publicKey = publicKey;
            message = store.message; 
            checkTx = True;
            ];  

    // Execute below for the first transaction
    if(store.checkTx = False) then {
       firstReturn :=  
       record [publicKey = publicKey;
       message = store.message; 
       checkTx = True;
       ];    
    
    // Execute this for 2nd Tx and onwards
    } else {

        // Do signature verification for new public key
        if(Crypto.check(store.publicKey, spsig, hexOptimisedPublicKey)) then {
            firstReturn :=
        record [
            publicKey  = publicKey; // update new
            message  = store.message;     
            checkTx = True
        ];

         // If sign verify fails, retain old information
        } else {
            firstReturn :=  
                record [publicKey = store.publicKey; // retain previous 
                message = store.message; 
                checkTx = True;
                ];
            }   
        }
 
    } with firstReturn

function storeInSC (const originalMsg : string; const spsig : signature; const store : storage) : storage is 
 block {
  
  var hexBinary : bytes := Bytes.pack(originalMsg) ;  

  var returnname :=
      record [
        publicKey  = store.publicKey;
        message  = store.message;
        checkTx = True
      ];
    if(Crypto.check(store.publicKey, spsig, hexBinary)) then {
        returnname :=
      record [
        publicKey  = store.publicKey;
        message  = originalMsg;      
        checkTx = True
      ];
    } else {
        returnname :=
      record [
        publicKey  = store.publicKey;
        message  = store.message;
        checkTx = True
      ];
    }
} with returnname

function main (const action : parameter; const store : storage) : return is
 ((nil : list (operation)),    // No operations
  case action of
      StorePublic (pbKey, sig) -> storePublic (pbKey, sig, store)       
    | StoreMessage (originalMsg, spsig) -> storeInSC (originalMsg, spsig, store)  
  end)
