#include <iostream>
#include <getopt.h>
#include <string.h>
#include <gmp.h>
#include <regex>

#define MESSAGE_SIZE_EXPONENT 64
#define MESSAGE_SIZE 2^64


using namespace std;

string hash(){
    return "";
}

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
    else{
        cerr << "Used unknown argument" << char(argument) << endl;
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
    bool ok = true;
    cout << "Hello world!" << endl;
    Args args;
    int c;

    while(args.parsed_correctly && (c = getopt(argc, argv, "csvek:m:n:a:")) != -1){
        args_switch(c, &args);
    }
    if(args.parsed_correctly){
        print_all_arguments(args);
    }
    int count_options = args.option_c + args.option_e + args.option_s + args.option_v;
    if(count_options != 1){
        cerr << "Different number of selected options. Should be 1, is " << count_options << "." << endl;
        args.parsed_correctly = false;
    }
    return args;
}

void do_stuff(Args args){
    
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