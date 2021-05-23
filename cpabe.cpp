// pk = public key
// sk = secret key
// prefix m = master

#include <iostream>
#include <string>
#include <cassert>
#include <openabe/openabe.h>

using namespace std;
using namespace oabe;
using namespace oabe::crypto;

int main(int argc, char **argv) {
    InitializeOpenABE();
    cout << "Testing CP-ABE" << endl;
    OpenABECryptoContext cpabe("CP-ABE");

    cout << "\n################## Setup ##################\n";
    cpabe.generateParams();
    string mpk, msk;
    cpabe.exportPublicParams(mpk);
    cpabe.exportSecretParams(msk);
    cout << "Master public key:\n" << mpk << endl;
    cout << "Master secret key:\n" << msk << endl;
    cout << "###########################################\n\n";


    cout << "\n################# Encrypt #################\n";
    string pt = "hello world!";
    vector<string> policies = {"attr1 or attr2", "attr1 and attr2"};
    vector<string> ct(policies.size());
    for (size_t i = 0; i < policies.size(); i++) {
        cpabe.encrypt(policies[i], pt, ct[i]);
        cout << "Policy " << i+1 << ":\n\"" << policies[i] << "\"\n";
        cout << "Plaintext:\n" << pt << endl;
        cout << "Ciphertext:\n" << ct[i] << "\n\n";
    }
    cout << "#########################################\n\n";


    cout << "\n################# KeyGen ##################\n";
    cpabe.enableKeyManager("user");
    cpabe.enableVerbose();  // print the matching log to stdout
    string recvAttrs = "|attr1|", sk;
    cpabe.keygen(recvAttrs, "key0");
    cpabe.exportUserKey("key0", sk);
    cpabe.importUserKey("key0", sk); // import into key manager
    cout << "Receiver's attributes:\n\"" << recvAttrs << "\"\n";
    cout << "Generated key:\n" << sk << endl;
    cout << "#########################################\n\n";

    cout << "\n################# Decrypt #################\n";
    string rePt;
    bool result;
    for (size_t i = 0; i < ct.size(); i++) {
        cout << "Policy " << i+1 << ": (the receiver shouldn't know this)\n\"" << policies[i] << "\"\n";
        cout << "Decrypt:\n";
        try {
            result = cpabe.decrypt(ct[i], rePt);
            if (result && pt == rePt) cout << "Recovered message: " << rePt << "\n\n";
        } catch (oabe::ZCryptoBoxException& ex) {
            cout << ex.what() << endl;
            cout << "Failed to recover the message.\n\n";
        }
    }
    cout << "#########################################\n\n";

    ShutdownOpenABE();

    return 0;
}
