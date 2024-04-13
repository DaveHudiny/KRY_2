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
    string chs = ""; // -m -- MAC checksum for verification or extension attack
    int key_length = 0; // -n -- length of key for attack
    string msg_a = ""; // -a -- message for extension attack
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
        cerr << "Message does not match with regex " << endl; 
    }
}

void args_switch(int c, Args *args){
    regex key_regex_expression("^[A-Fa-f0-9]*$");
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
            break;
        case 'm':
            args->chs = optarg;
            break;
        case 'n':
            args->key_length = stoi(optarg);
            break;
        case 'a':
            args->msg_a = optarg;
            if(!regex_match(optarg, message_regex_expression)){
                print_wrong_arguments(c);
                args->parsed_correctly = false;
            }
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
    cin >> message;
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

string read_with_padding(){
    string message = read_text_from_std();
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
    message = append_64_bit_padding(message, length - IMPLICIT_PADDING_SIZE);
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
    for(uint32_t i = 0; i < 16; i++){
        W[i] = block[i];
        
    }
    for(uint32_t i = 16; i < 64; i++){
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

    for(uint32_t i = 0; i < 64; i++)
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
    for (size_t i = 0; i < message.length(); i += 4) {
        uint32_t word = 0;
        for (size_t j = 0; j < 4; j++) {
            word |= (static_cast<uint32_t>(message[i + j]) & 0xFF) << (FIXED_CHAR_SIZE * (3 - j));
        }
        message_words.push_back(word);
    }
    return message_words;
}

string convert_hash_words_to_string(uint32_t H[]){
    string hashed_message = "";
    for(uint32_t i = 0; i < 8; i++)
    {
        cout << "Hoho";
        uint32_t word = H[i];
        for (uint32_t j = 0; j < 4; j++){
            hashed_message += (char) (H[i] >> j * 8) & 0xFF;
        }
    }
    return hashed_message;
}

string sha256_hash(string message){
    uint32_t H[8];
    vector<uint32_t> message_words = convert_string_to_words(message);
    init_hash(H);
    uint64_t N = (compute_length(message)) / BLOCK_SIZE;
    for(uint64_t i = 0; i < N; i++){
        vector<uint32_t> block(message_words.begin() + (i * (BLOCK_SIZE / WORD_SIZE)), message_words.begin() + ((i+1) * (BLOCK_SIZE / WORD_SIZE)));
        process_block(block, H);
    }
    string hash_text = convert_hash_words_to_string(H);
    return hash_text;
}

void read_and_hash(){
    string message = read_with_padding();
    cout << "Length " << compute_length(message) << endl;
    string hash_result = sha256_hash(message);
    cout << hash_result << endl;
    // print_as_bits(message);
}

void do_stuff(Args args){
    if(args.option_c){
        read_and_hash();
    }
    else{
        cerr << "not implemented yet" << endl; //TODO
    }
}

int main(int argc, char *argv[]){
    Args parsed_args = parse_args(argc, argv);
    if(parsed_args.parsed_correctly){
        do_stuff(parsed_args);
    }
    else{
        return 1;
    }
    return 0;
}