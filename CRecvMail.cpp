#include "CRecvMail.h"
#include "time.h"
#include <fstream>
#include <sstream>
#pragma comment(lib, "WSOCK32")
#pragma comment(lib, "ws2_32")
//
#include <errno.h>
#include <iostream>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <string>
#pragma comment(lib, "libcrypto.lib")
#pragma comment(lib, "libssl.lib")
extern "C" {
#include <openssl/applink.c>
};

using namespace std;

#define OPENSSLKEY "test.key"
#define PUBLICKEY "test_pub.key"
#define BUFFSIZE 1024
char* myBase64Decode(char* input, int length, bool with_new_line);
char* my_decrypt(char* str, char* path_key); // decrypt

const std::string _AppOctStrmContent_encode_chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
std::string globalr = "";
int count = 0;
CRecvMail::CRecvMail(void)
{
}

CRecvMail::~CRecvMail(void)
{
}

bool CRecvMail::Connent()
{

    if (!CReateSocket()) {
        m_logInfo.logInfo("Connect Failed.");
        return false;
    }

    if (!Logon()) {
        m_logInfo.logInfo("Login Failed.");
        return false;
    }

    if (!listMailBox()) //list
    {
        m_logInfo.logInfo("Failed.");
        return false;
    }
    std::cout << "Mail(s) all above" << endl;
    std::cout << "Input mail number:" << endl;
    std::string mailnumber;
    cin >> mailnumber;
    if (!getMail(mailnumber)) //list
    {
        m_logInfo.logInfo("Failed.");
        return false;
    }
    return true;
}

void CRecvMail::setServerName(const std::string server_name) //pop3 host server
{
    m_ServerName = server_name;
}

void CRecvMail::setUserName(const std::string user_name)
{
    m_UserName = user_name;
}

void CRecvMail::setUserPwd(const std::string user_pwd)
{
    m_UserPwd = user_pwd;
}

string& CRecvMail::replace_all(string& str, const string& old_value, const string& new_value)
{
    while (true) {
        string::size_type pos(0);
        if ((pos = str.find(old_value)) != string::npos)
            str.replace(pos, old_value.length(), new_value);
        else
            break;
    }
    return str;
}

// char -> Base64
std::string CRecvMail::Base64Encode(std::string in_str)
{
    std::string out_str;
    unsigned char c1, c2, c3;
    int i = 0;
    int len = in_str.length();

    while (i < len) {
        // read the first byte
        c1 = in_str[i++];
        if (i == len) // pad with "="
        {
            out_str += _AppOctStrmContent_encode_chars[c1 >> 2];
            out_str += _AppOctStrmContent_encode_chars[(c1 & 0x3) << 4];
            out_str += "==";
            break;
        }
        // read the second byte
        c2 = in_str[i++];
        if (i == len) // pad with "="
        {
            out_str += _AppOctStrmContent_encode_chars[c1 >> 2];
            out_str += _AppOctStrmContent_encode_chars[((c1 & 0x3) << 4) | ((c2 & 0xF0) >> 4)];
            out_str += _AppOctStrmContent_encode_chars[(c2 & 0xF) << 2];
            out_str += "=";
            break;
        }
        // read the third byte
        c3 = in_str[i++];
        // convert into four bytes string
        out_str += _AppOctStrmContent_encode_chars[c1 >> 2];
        out_str += _AppOctStrmContent_encode_chars[((c1 & 0x3) << 4) | ((c2 & 0xF0) >> 4)];
        out_str += _AppOctStrmContent_encode_chars[((c2 & 0xF) << 2) | ((c3 & 0xC0) >> 6)];
        out_str += _AppOctStrmContent_encode_chars[c3 & 0x3F];
    }
    return out_str;
}

int CRecvMail::sendRequest(const std::string content, bool bout)
{
    int len_s = send(_socket, content.c_str(), content.length(), 0);
    if (len_s < 0) {
        m_logInfo.logInfo("[ERROR]SEND:%s", content.c_str());
        return false;
    }

    m_logInfo.logInfo("[INFO]SEND:%s", content.c_str());

    return len_s;
}

bool CRecvMail::rcvResponse(const std::string expected_response, bool flag)
{
    int recv_bytes = 0;
    string filename = "";
    stringstream sstr;
    sstr << count;
    string str = sstr.str();
    // char response_buffer[POP_MAX_BUFFER_SIZE];
    char response_buffer[65536];
    if ((recv_bytes = recv(_socket, response_buffer, POP_MAX_BUFFER_SIZE, 0)) < 0) {
        m_logInfo.logInfo("[ERROR]RECV:%s", expected_response.c_str());
        return false;
    }
    std::string response(response_buffer, recv_bytes);
    if (flag) {
        filename = "Recv";
        filename += str;
        ofstream fout;
        fout.open(str);
        fout << response_buffer;
        fout.close();
        count++;
    }

    m_logInfo.logInfo("[INFO]RECV(%s):%s", expected_response.c_str(), response.c_str());
    if ((response.substr(0, 3) != expected_response) && (expected_response != "")) {
        return false;
    }
    return true;
}

std::string CRecvMail::prepareDate()
{
    char date_string[POP_MAX_BUFFER_SIZE];

    time_t seconds;
    time(&seconds);
    strftime(date_string, POP_MAX_BUFFER_SIZE,
        "%a, %d %b %y %H:%M:%S +0800",
        localtime(&seconds)); // +0800 maybe hard code

    return date_string;
}

bool CRecvMail::CReateSocket()
{
    WORD wVersionRequested;
    WSADATA wsaData;
    int err;
    wVersionRequested = MAKEWORD(2, 2);
    err = WSAStartup(wVersionRequested, &wsaData);
    if (err != 0) {
        m_logInfo.logInfo("WSAStartup Failed");
        return false;
    }
    if (LOBYTE(wsaData.wVersion) != 2 || HIBYTE(wsaData.wVersion) != 2) {
        WSACleanup();
        return false;
    }
    _socket = socket(AF_INET, SOCK_STREAM, IPPROTO_IP);
    if (_socket == INVALID_SOCKET) {
        m_logInfo.logInfo("socket Creationg Failed");
        return false;
    }

    sockaddr_in servaddr;
    memset(&servaddr, 0, sizeof(sockaddr_in));
    servaddr.sin_family = AF_INET;
    servaddr.sin_port = htons(POP_SERVICE_PORT); // port 110

    struct hostent* hp = gethostbyname(m_ServerName.c_str()); //
    if (hp == NULL) {
        DWORD dwErrCode = GetLastError();
        return false;
    }
    servaddr.sin_addr.s_addr = *(int*)(*hp->h_addr_list);

    int ret = connect(_socket, (sockaddr*)&servaddr, sizeof(servaddr)); //
    if (ret == SOCKET_ERROR) {
        DWORD dwErr = GetLastError();
        return false;
    }
    if (!rcvResponse("+OK", 0))
        return false;
    return true;
}

bool CRecvMail::Logon()
{
    char local_host[POP_MAX_BUFFER_SIZE];
    std::string msg;
    msg = "user ";
    msg += m_UserName;
    msg += "\r\n";
    sendRequest(msg);
    if (!rcvResponse("+OK", 0)) {
        return false;
    }
    msg = "pass ";
    msg += m_UserPwd;
    msg += "\r\n";
    sendRequest(msg);
    if (!rcvResponse("+OK", 0)) {
        return false;
    }

    return true; // Login
}
bool CRecvMail::listMailBox()
{
    char local_host[POP_MAX_BUFFER_SIZE];
    std::string msg;
    msg = "list\r\n";
    sendRequest(msg);
    if (!rcvResponse("+OK", 0)) {
        return false;
    }

    return true;
}
bool CRecvMail::getMail(std::string mailnum)
{
    count = 0;
    char local_host[POP_MAX_BUFFER_SIZE];
    std::string msg;
    msg = "retr ";
    msg += mailnum;
    msg += "\r\n";
    sendRequest(msg);
    if (!rcvResponse("+OK", 1)) {
        return false;
    }
    // rcvResponse("");
    rcvResponse("", 1);
    system("python proc.py");
    Sleep(3000);

    // process
    char buffer[10000];
    char* b = buffer;
    //string buffer;
    ifstream in("content");
    /*if (!in.is_open()) {
        cout << "Error opening file";
        exit(1);
    }*/
    in.getline(buffer, 10000);
    char* b64de = myBase64Decode(b, strlen(b), false);
    char* decrypted = my_decrypt(b64de, OPENSSLKEY);
    cout << decrypted << endl;

    // cout << b << endl;

    return true;
}

char* myBase64Decode(char* input, int length, bool with_new_line)
{
    BIO* b64 = NULL;
    BIO* bmem = NULL;
    char* buffer = (char*)malloc(length);
    memset(buffer, 0, length);

    b64 = BIO_new(BIO_f_base64());
    if (!with_new_line) {
        BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    }
    bmem = BIO_new_mem_buf(input, length);
    bmem = BIO_push(b64, bmem);
    BIO_read(bmem, buffer, length);

    BIO_free_all(bmem);

    return buffer;
}

//decrypt
char* my_decrypt(char* str, char* path_key)
{
    char* p_de = NULL;
    RSA* p_rsa = NULL;
    FILE* file = NULL;
    int rsa_len = 0;

    file = fopen(path_key, "rb");
    if (!file) {
        perror("fopen() error");
        goto End;
    }

    //get prikey
    if ((p_rsa = PEM_read_RSAPrivateKey(file, NULL, NULL, NULL)) == NULL) {
        ERR_print_errors_fp(stdout);
        goto End;
    }

    //keylen
    rsa_len = RSA_size(p_rsa);

    //malloc
    p_de = (char*)malloc(rsa_len + 1);
    if (!p_de) {
        perror("malloc() error ");
        goto End;
    }
    memset(p_de, 0, rsa_len + 1);

    //de
    if (RSA_private_decrypt(rsa_len, (unsigned char*)str, (unsigned char*)p_de, p_rsa, RSA_NO_PADDING) < 0) {
        perror("RSA_public_encrypt() error ");
        goto End;
    }

End:
    //release
    if (p_rsa)
        RSA_free(p_rsa);
    if (file)
        fclose(file);

    return p_de;
}
