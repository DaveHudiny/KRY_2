#include "kry.hpp"

using namespace std;

#define MESSAGE_SIZE_EXPONENT 64
#define MESSAGE_SIZE 2^64

#define DEBUG_MODE false

#define LAST_BLOCK_SIZE 448
#define BLOCK_SIZE 512
#define IMPLICIT_PADDING_SIZE 8
#define WORD_SIZE 32
#define FIXED_CHAR_SIZE 8


typedef struct{
    bool option_c = false; // Task 1 -- compute checksum
    bool option_s = false; // Task 2 -- compute MAC
    bool option_v = false; // Task 3 -- verify MAC
    bool option_e = false; // Task 4 -- extension attack
    string key = ""; // -k -- key
    bool key_set = false;
    string chs = ""; // -m -- MAC checksum for verification or extension attack
    bool chs_set = false;
    uint64_t key_length = 0; // -n -- length of key for attack
    bool key_length_set = false;
    string msg_a = ""; // -a -- message for extension attack
    bool msg_a_set = false;
    bool parsed_correctly = true;
}Args;

void print_all_arguments(Args args){
    cerr << "option_c " << args.option_c << endl;
    cerr << "option_s " << args.option_s << endl;
    cerr << "option_v " << args.option_v << endl;
    cerr << "option_e " << args.option_e << endl;
    cerr << "key " << args.key << endl; 
    cerr << "chs " << args.chs << endl;
    cerr << "key_length " << args.key_length << endl;
    cerr << "msg_a " << args.msg_a << endl;
    cerr << "parsed_correctly " << args.parsed_correctly << endl; 
}

void print_help(){
    cerr << "Usage of program: " << endl;
    cerr << "TODO" << endl;
}

void print_wrong_arguments(int argument){
    if(argument == 'k'){
        cerr << "Key does not match with regex " << endl; 
    }
}

void args_switch(int c, Args *args){
    regex key_regex_expression("^[A-Za-z0-9]*$");
    regex message_regex_expression("^[a-zA-Z0-9!#$%&’\"()*+,\\-.\\/\\\\:;<>=?@\\[\\]\\^_{}|~]*$");
    switch(c){
        case 'c':
            args->option_c = true;
            break;
        case 's':
            args->option_s = true;
            break;
        case 'v':
            args->option_v = true;
            break;
        case 'e':
            args->option_e = true;
            break;
        case 'k':
            args->key = optarg;
            if(!regex_match(args->key, key_regex_expression)){
                print_wrong_arguments(c);
                args->parsed_correctly = false;
            }
            args->key_set = true;
            break;
        case 'm':
            args->chs = optarg;
            args->chs_set = true;
            break;
        case 'n':
            args->key_length = stoll(optarg);
            args->key_length_set = true;
            break;
        case 'a':
            args->msg_a = optarg;
            if(!regex_match(optarg, message_regex_expression)){
                print_wrong_arguments(c);
                args->parsed_correctly = false;
            }
            args->msg_a_set = true;
            break;
        default:
            print_wrong_arguments(c);
            args->parsed_correctly = false;
            break;
        }
}

Args parse_args(int argc, char *argv[]){
    Args args;
    int c;

    while(args.parsed_correctly && (c = getopt(argc, argv, "csvek:m:n:a:")) != -1){
        args_switch(c, &args);
    }
    int count_options = args.option_c + args.option_e + args.option_s + args.option_v;
    if(count_options != 1){
        cerr << "Different number of selected tasks. Should be 1, is " << count_options << "." << endl;
        args.parsed_correctly = false;
    }
    if(args.parsed_correctly && DEBUG_MODE){
        print_all_arguments(args);
    }
    return args;
}

string read_text_from_std(){
    string message;
    getline(cin, message, '\0');
    return message;
}

void print_as_bits(string str){
    for(auto &a : str){
        bitset<8> y(a);
        cout << y << " ";
    }
    cout << endl;
}

uint64_t compute_length(string str){
    uint64_t str_len = str.length();
    return str_len * FIXED_CHAR_SIZE;
}

string append_64_bit_padding(string message, uint64_t length){
    for (int i = 7; i >= 0; i--) {
        char byte = (length >> (8 * i)) & 0xFF;
        message += byte;
    }
    return message;
}

string add_padding(string message, uint64_t fake_size_modifier = 0){
    message += 128;
    const char zero = 0;
    uint64_t length = compute_length(message);
    uint64_t num_blocks = length / BLOCK_SIZE;
    if(length - (num_blocks * BLOCK_SIZE) > LAST_BLOCK_SIZE){
        num_blocks += 1;
    }
    if((compute_length(message) % BLOCK_SIZE) >= LAST_BLOCK_SIZE)
    {
        while((compute_length(message) % BLOCK_SIZE) >= LAST_BLOCK_SIZE){
            message += zero;
        }
    }
    while((compute_length(message) % BLOCK_SIZE) < LAST_BLOCK_SIZE){
        message += zero;
    }
    message = append_64_bit_padding(message, (length - IMPLICIT_PADDING_SIZE) + fake_size_modifier);
    return message;
}

void init_hash(uint32_t H[]){
    H[0] = 0x6a09e667;
    H[1] = 0xbb67ae85;
    H[2] = 0x3c6ef372;
    H[3] = 0xa54ff53a;
    H[4] = 0x510e527f;
    H[5] = 0x9b05688c;
    H[6] = 0x1f83d9ab;
    H[7] = 0x5be0cd19;
}

uint32_t Ch(uint32_t x, uint32_t y, uint32_t z){
    return (x & y) ^ (~x & z);
}

uint32_t Maj(uint32_t x, uint32_t y, uint32_t z){
    return (x & y) ^ (x & z) ^ (y & z);
}

uint32_t Rotate_Right(uint32_t word, uint32_t n){
    uint32_t right_part = (word >> n);
    uint32_t left_part = (word << (WORD_SIZE - n));
    return left_part | right_part;
}

uint32_t sum_0(uint32_t word){
    return Rotate_Right (word, 2) ^ Rotate_Right (word, 13) ^ Rotate_Right (word, 22);
}

uint32_t sum_1(uint32_t word){
    return Rotate_Right (word, 6) ^ Rotate_Right (word, 11) ^ Rotate_Right (word, 25);
}

uint32_t sigma_0(uint32_t word){
    return Rotate_Right (word, 7) ^ Rotate_Right (word, 18) ^ (word >> 3);
}

uint32_t sigma_1(uint32_t word){
    return Rotate_Right (word, 17) ^ Rotate_Right (word, 19) ^ (word >> 10);
    
}

void print_messages(vector<uint32_t> message_words){
    for(auto &word : message_words){
        bitset<32> hexa(word);
        cout << hexa;
    }
    cout << endl;
}

void process_block(vector<uint32_t> block, uint32_t H[]){
    uint32_t W[64];
    for(int i = 0; i < 16; i++){
        W[i] = block[i];
        
    }
    for(int i = 16; i < 64; i++){
        W[i] = sigma_1(W[i-2]) + W[i-7] + sigma_0(W[i-15]) + W[i-16];
    }
    uint32_t a = H[0];
    uint32_t b = H[1];
    uint32_t c = H[2];
    uint32_t d = H[3];
    uint32_t e = H[4];
    uint32_t f = H[5];
    uint32_t g = H[6];
    uint32_t h = H[7];

    for(int i = 0; i < 64; i++)
    {
        uint32_t T1 = h + sum_1(e) + Ch(e, f, g) + CONSTANTS[i] +W[i];
        uint32_t T2 = sum_0(a) + Maj(a, b, c);
        h = g;
        g = f;
        f = e;
        e = d + T1;
        d = c;
        c = b;
        b = a;
        a = T1 + T2;
    }
    H[0] = a + H[0];
    H[1] = b + H[1];
    H[2] = c + H[2];
    H[3] = d + H[3];
    H[4] = e + H[4];
    H[5] = f + H[5];
    H[6] = g + H[6];
    H[7] = h + H[7];
}

vector<uint32_t> convert_string_to_words(string message){
    vector<uint32_t> message_words;
    for (int i = 0; i < message.length(); i += 4) {
        uint32_t word = 0;
        for (int j = 0; j < 4; j++) {
            word |= (static_cast<uint32_t>(message[i + j]) & 0xFF) << (FIXED_CHAR_SIZE * (3 - j));
        }
        message_words.push_back(word);
    }
    return message_words;
}

string convert_hash_words_to_string(uint32_t H[]){
    string hashed_message = "";
    for(int i = 0; i < 8; i++)
    {
        uint32_t word = H[i];
        for(int j = 3; j >= 0; j--){
            hashed_message += (char) (word >> j * FIXED_CHAR_SIZE) & 0xFF;
        }
    }
    return hashed_message;
}

void print_hexadecimal(string text){
    for(size_t i = 0; i < 32; i++){
        cout << hex << setw(2) << setfill('0') << (int) (uint8_t) text[i];
    }
    cout << endl;
}

string create_hexadecimal(string text){
    string hexamessage = "";
    for(size_t i = 0; i < 32; i++){
        stringstream stream;
        stream << hex << setw(2) << setfill('0') << (int) (uint8_t) text[i];
        hexamessage += stream.str();
    }
    return hexamessage;
}

string sha256_hash(string message){
    uint32_t H[8];
    vector<uint32_t> message_words = convert_string_to_words(message);
    init_hash(H);
    uint64_t N = (compute_length(message)) / BLOCK_SIZE;
    for(size_t i = 0; i < N; i++){
        vector<uint32_t> block(message_words.begin() + (i * (BLOCK_SIZE / WORD_SIZE)), message_words.begin() + ((i+1) * (BLOCK_SIZE / WORD_SIZE)));
        process_block(block, H);
    }
    string hashed_text = convert_hash_words_to_string(H);
    return hashed_text;
}

int read_and_hash(){
    string original_message = read_text_from_std();
    string message = add_padding(original_message);
    string hash_result = sha256_hash(message);
    print_hexadecimal(hash_result);
    return 0;
}

int read_and_hash_with_key(Args args){
    string original_message = read_text_from_std();
    string message = args.key + original_message;
    string padded_message = add_padding(message);
    string hash_result = sha256_hash(padded_message);
    print_hexadecimal(hash_result);
    return 0;
}

int read_and_compare_hash_with_mac(Args args){
    string original_message = read_text_from_std();
    string message = args.key + original_message;
    string padded_message = add_padding(message);
    string hash_result = sha256_hash(padded_message);
    string hexa_message = create_hexadecimal(hash_result);
    if(hexa_message != args.chs){
        return 1;
    }
    return 0;
}

void init_modified_hash(uint32_t H[], string old_hash){
    for(size_t i = 0; i < 8; i++){
        string word = "";
        for(size_t j = 0; j < 8; j++){
            word += old_hash[i * 8 + j];
        }
        H[i] = (uint32_t) stoll(word, 0, 16);
    }
}

string modified_sha256_hash(string message, uint32_t H[]){
    vector<uint32_t> message_words = convert_string_to_words(message);
    uint64_t N = (compute_length(message)) / BLOCK_SIZE;
    for(size_t i = 0; i < N; i++){
        vector<uint32_t> block(message_words.begin() + (i * (BLOCK_SIZE / WORD_SIZE)), message_words.begin() + ((i+1) * (BLOCK_SIZE / WORD_SIZE)));
        process_block(block, H);
    }
    string hashed_text = convert_hash_words_to_string(H);
    return hashed_text;
}

void print_nasty_request(string original_message, string nasty_message, uint64_t key_length){
    bool padding_part = false;
    for(size_t i = 0; i < original_message.length(); i++){
        if(i < key_length){
            continue;
        }
        if(static_cast<unsigned char>(original_message[i]) == 128){
            padding_part = true;
        }
        if(!padding_part){
            cout << original_message[i];
        }
        else{
            stringstream stream;
            stream << hex << setw(2) << setfill('0') << (int) (uint8_t) original_message[i];
            cout << "\\x" << stream.str();
        }
    }
    for(auto &c : nasty_message){
        cout << c;
    }
    cout << endl;
}


int do_extension_attack(Args args){
    string original_message = read_text_from_std();
    string fake_password = "";
    for(size_t i = 0; i < args.key_length; i++){
        fake_password += '1';
    }
    original_message = add_padding(fake_password + original_message);
    string message = args.msg_a;
    uint64_t fake_size_modifier = compute_length(original_message);
    message = add_padding(message, fake_size_modifier);
    uint32_t H[8];
    init_modified_hash(H, args.chs);
    string hash_text = modified_sha256_hash(message, H);
    print_hexadecimal(hash_text);
    print_nasty_request(original_message, args.msg_a, args.key_length);
    return 0;
}

int do_stuff(Args args){
    int returnor;
    if(args.option_c){
        returnor = read_and_hash();
    }
    else if(args.option_s){
        if(!args.key_set){
            cerr << "You have to write key when using option -s." << endl;
            returnor = 1;
        }
        else{
            returnor = read_and_hash_with_key(args);
        }
    }
    else if(args.option_v){
        if(args.chs_set && args.key_set){
            returnor = read_and_compare_hash_with_mac(args);
        }
        else{
            cerr << "You have to set parameters -k and -m with option -v." << endl;
            returnor = 2;
        }
    }
    else if(args.option_e){
        if(args.chs_set && args.key_length_set && args.msg_a_set){
            returnor = do_extension_attack(args);
        }
        else{
            cerr << "You have to set parameters -n, -m and -a if using parameter e.";
            returnor = 1;
        }
    }
    else{
        cerr << "not implemented yet" << endl; //TODO
        returnor = 1;
    } 

    return returnor;
}

int main(int argc, char *argv[]){
    Args parsed_args = parse_args(argc, argv);
    if(parsed_args.parsed_correctly){
        return do_stuff(parsed_args);
    }
    return 1;
}