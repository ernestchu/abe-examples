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
    cout << "Testing KP-ABE" << endl;
    OpenABECryptoContext kpabe("KP-ABE");

    cout << "\n################## Setup ##################\n";
    kpabe.generateParams();
    string mpk, msk;
    kpabe.exportPublicParams(mpk);
    kpabe.exportSecretParams(msk);
    cout << "Master public key:\n" << mpk << endl;
    cout << "Master secret key:\n" << msk << endl;
    cout << "###########################################\n\n";

    cout << "\n################# Encrypt #################\n";
    string pt = "hello world!";
    vector<string> attributes = {"|attr1|attr2|", "|attr3|attr4|"};
    vector<string> ct(attributes.size());
    for (size_t i = 0; i < attributes.size(); i++) {
        kpabe.encrypt(attributes[i], pt, ct[i]);
        cout << "Attribute set" << i+1 << ":\n\"" << attributes[i] << "\"\n";
        cout << "Plaintext:\n" << pt << endl;
        cout << "Ciphertext:\n" << ct[i] << "\n\n";
    }
    cout << "#########################################\n\n";
    
    cout << "\n################# KeyGen ##################\n";
    kpabe.enableKeyManager("user");
    kpabe.enableVerbose();  // print the matching log to stdout
    string policy = "(attr1 and attr3) or attr2", sk;
    kpabe.keygen(policy, "key0");
    kpabe.exportUserKey("key0", sk);
    kpabe.importUserKey("key0", sk); // import into key manager
    cout << "CA's policy:\n\"" << policy << "\"\n";
    cout << "Generated key:\n" << sk << endl;
    cout << "#########################################\n\n";

    cout << "\n################# Decrypt #################\n";
    string rePt;
    bool result;
    for (size_t i = 0; i < ct.size(); i++) {
        cout << "Sender's attributes " << i+1 << ":\n\"" << attributes[i] << "\"\n";
        cout << "Decrypt:\n";
        try {
            result = kpabe.decrypt(ct[i], rePt);
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
