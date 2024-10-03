#include <cstdint>
#include <iostream>
#include <random>
#include <vector>
#include "seal/seal.h"

using namespace seal;
using namespace std;

template <class T>
void print(const vector<T>& v)
{
    cout << "{ ";
    if (v.size() > 8)
    {
        for (size_t i = 0; i < 4; i++) cout << ' ' << v[i];
        cout << " ...";
        for (size_t i = v.size() - 4; i < v.size(); i++) cout << ' ' << v[i];
    }
    else for (size_t i = 0; i < v.size(); i++) cout << ' ' << v[i];
    cout << "}\n";
}

int main()
{

    EncryptionParameters params(scheme_type::ckks);
    size_t n = 1<<13;
    params.set_poly_modulus_degree(n);
    params.set_coeff_modulus(CoeffModulus::Create(n, {60, 40, 40, 60}));

    uint64_t log2_scale = 40;
    double scale = pow(2.0, log2_scale);
    
    SEALContext context(params);
    KeyGenerator keygen(context);
    SecretKey secret_key = keygen.secret_key();
    PublicKey public_key;
    keygen.create_public_key(public_key);
    RelinKeys relin_keys;
    keygen.create_relin_keys(relin_keys);
    GaloisKeys gal_keys;
    keygen.create_galois_keys(gal_keys);
    CKKSEncoder encoder(context);
    Encryptor encryptor(context, public_key);
    Evaluator evaluator(context);
    Decryptor decryptor(context, secret_key);

    size_t slot_count = encoder.slot_count();
    cout << "Number of slots: " << slot_count << endl;

    vector<double> input(slot_count, 0);
    for (size_t i = 0; i < slot_count; i++)
        input[i] = (double)i;

    cout << "\nInput vector:" << endl;
    print(input);

    {   
        cout << "\nStandard Encoding" << endl;

        Plaintext plain;
        encoder.encode(input, scale, plain);

        vector<double> output;
        encoder.decode(plain, output);

        cout << "Output vector:" << endl;
        print(output);
    }

    {
        cout << "\nProposed Partial Encoding" << endl;

        vector<uint64_t> encoded;
        encoder.encode(input, scale, encoded);

        cout << "Encoded vector: " << encoded.size() << endl;
        print(encoded);

        Plaintext plain;
        encoder.encode(encoded, scale, plain);

        vector<double> output;
        encoder.decode(plain, output);
        
        cout << "Output vector:" << endl;
        print(output);
    }

    {   
        cout << "\nStandard Encoding with Encryption" << endl;

        Plaintext plain;
        encoder.encode(input, scale, plain);

        Ciphertext encrypted;
        encryptor.encrypt(plain, encrypted);

        Plaintext plain_decrypted;
        decryptor.decrypt(encrypted, plain_decrypted);

        vector<double> output;
        encoder.decode(plain_decrypted, output);

        cout << "Output vector:" << endl;
        print(output);
    }

    {
        cout << "\nProposed Partial Encoding with Encryption" << endl;

        vector<uint64_t> encoded;
        encoder.encode(input, scale, encoded);

        cout << "Encoded vector: " << encoded.size() << endl;
        print(encoded);

        Plaintext plain;
        encoder.encode(encoded, scale, plain);

        Ciphertext encrypted;
        encryptor.encrypt(plain, encrypted);

        Plaintext plain_decrypted;
        decryptor.decrypt(encrypted, plain_decrypted);

        vector<double> output;
        encoder.decode(plain_decrypted, output);
        
        cout << "Output vector:" << endl;
        print(output);
    }
    
    {
        cout << "\nProposed Partial Encoding with Additive Secret Sharing, Encryption, and Homomorphic Addition" << endl;

        random_device rd;
        mt19937 gen(rd());
        
        vector<uint64_t> encoded;
        encoder.encode(input, scale, encoded);

        cout << "Encoded vector: " << encoded.size() << endl;
        print(encoded);


        auto &coeff_modulus = params.coeff_modulus();
        std::size_t coeff_modulus_size = coeff_modulus.size();
        std::size_t coeff_count = params.poly_modulus_degree();
        cout << "coeff_modulus_size: " << coeff_modulus_size << endl;
        cout << "coeff_count: " << coeff_count << endl;

        // print moduli
        for (size_t i = 0; i < coeff_modulus_size; i++)
            cout << "modulus[" << i << "]: " << coeff_modulus[i].value() << endl;

        
        vector<uint64_t> encoded_share1(encoded.size());
        vector<uint64_t> encoded_share2(encoded.size());
        for (size_t i = 0; i < coeff_modulus_size - 1; i++)
        {
            uint64_t mod = coeff_modulus[i].value();
            uniform_int_distribution<uint64_t> dist(0, coeff_modulus[i].value()-1);
            for (size_t j = 0; j < coeff_count; j++)
            {
                auto idx = i * coeff_count + j;
                uint64_t r = dist(gen);
                encoded_share1[idx] = (encoded[idx] - r + mod) % mod;
                encoded_share2[idx] = r;
            }
        }
        cout << "Encoded share 1: " << encoded_share1.size() << endl;
        print(encoded_share1);
        cout << "Encoded share 2: " << encoded_share2.size() << endl;
        print(encoded_share2);

        Plaintext plain_share1, plain_share2;
        encoder.encode(encoded_share1, scale, plain_share1);
        encoder.encode(encoded_share2, scale, plain_share2);

        Ciphertext encrypted_share1;
        encryptor.encrypt(plain_share1, encrypted_share1);

        evaluator.add_plain_inplace(encrypted_share1, plain_share2);

        Plaintext plain_decrypted;
        decryptor.decrypt(encrypted_share1, plain_decrypted);

        vector<double> output;
        encoder.decode(plain_decrypted, output);

        cout << "Output vector:" << endl;
        print(output);
    }
}