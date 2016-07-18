#include "FHE.h"
#include "EncryptedArray.h"
#include <NTL/lzz_pXFactoring.h>
#include <fstream>
#include <sstream>
#include <sys/time.h>

int main(int argc, char **argv)
{
    /* On our trusted system we generate a new key
     * (or read one in) and encrypt the secret data set.
     */

    long m=0, p=13, r=1; // Native plaintext space
                        // Computations will be 'modulo p'
    long L=8;          // Levels
    long c=3;           // Columns in key switching matrix
    long w=64;          // Hamming weight of secret key
    long d=0;
    long security = 128;
    ZZX G;
    m = FindM(security,L,c,p, d, 0, 0);

    FHEcontext context(m, p, r);
    // initialize context
    buildModChain(context, L, c);
    // modify the context, adding primes to the modulus chain
    FHESecKey secretKey(context);
    // construct a secret key structure
    const FHEPubKey& publicKey = secretKey;
    // an "upcast": FHESecKey is a subclass of FHEPubKey

    //if(0 == d)
    G = context.alMod.getFactorsOverZZ()[0];

   secretKey.GenSecKey(w);
   // actually generate a secret key with Hamming weight w

   addSome1DMatrices(secretKey);
   cout << "Generated key" << endl;

   EncryptedArray ea(context, G);
   // constuct an Encrypted array object ea that is
   // associated with the given context and the polynomial G

   long nslots = ea.size();
   cout << "nslots: " << nslots << endl;

   vector<long> vMult3;
   Ctxt ctMult3(publicKey);
   for(int i = 0 ; i < nslots; i++) {
        vMult3.push_back(i*3);
   }
   ea.encrypt(ctMult3, publicKey, vMult3);

   vector<long> v3;
   Ctxt ct3(publicKey);
   for(int i=0;i<nslots; i++){
	   v3.push_back(3);
   }
   ea.encrypt(ct3, publicKey, v3);


   vector<long> v7;
   Ctxt ct7(publicKey);
   for(int i=0; i<nslots; i++){
	   v7.push_back(7);
   }
   ea.encrypt(ct7, publicKey, v7);

   // On the public (untrusted) system we
   // can now perform our computation
   
   //Calculate 3x+7
   Ctxt ctEq = ctMult3;
   ctEq *= ct3;
   ctEq += ct7;

    vector<long> res;

    cout << "All computations are modulo " << std::pow(p,r) << "." << endl;
    
    ea.decrypt(ctEq, secretKey, res);
    for(int i=0; i<res.size(); i++){
        cout << "3* " << vMult3[i] << " +7 " <<  " = " << res[i] << endl;
    }
    return 0;
}

