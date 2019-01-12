/*
    Rebuilt lightweight SMTP
    Auther: ShiCong Liu, Xiaotian Jia.
    Last Modified: 2019-1-8 22:47:36
*/
#include "CSendMail.h"
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

#define OPENSSLKEY "test.key"
#define PUBLICKEY "test_pub.key"
#define BUFFSIZE 1024

using namespace std;
//
const std::string _AppOctStrmContent_encode_chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
char* Base64Encode(const char* input, int length, bool with_new_line);
char* Base64Decode(char* input, int length, bool with_new_line);
char* my_encrypt(char* str, char* path_key); // encrypt
char* my_decrypt(char* str, char* path_key); // decrypt
char* Base64Encode(const char* input, int length, bool with_new_line);
char* Base64Decode(char* input, int length, bool with_new_line);
// Class

CSendMail::CSendMail(void)
{
}

CSendMail::~CSendMail(void)
{
    clearReceiver();
    DeleteAllPath();
}

// Connect to SMTP Server
bool CSendMail::Connent()
{
    // Sender Info
    if (m_ServerName.empty() || m_UserName.empty() || m_UserPwd.empty()) {
        m_logInfo.logInfo("Connect Failed.Please set your login info.");
        return false;
    }

    if (!CReateSocket()) // Connect
    {
        m_logInfo.logInfo("Failed.");
        return false;
    }

    if (!Logon()) // Login
    {
        m_logInfo.logInfo("Failed.");
        return false;
    }
    return true;
}
// `````````````````[Utils]`````````````````
// Utils
bool CSendMail::SendMail(const std::string mail_title, const std::string send_content)
{
    // Parameters
    m_MailTitle = mail_title;
    m_TextBody = send_content;

    if (m_SenderName.empty() || m_SenderAddr.empty() || m_Receivers.empty()) {
        m_logInfo.logInfo("[SendMail]Parameter Error.");
        return false;
    }

    if (!SendHead()) // Headers
    {
        m_logInfo.logInfo("Header sent failed.");
        return false;
    }

    if (!SendTextBody()) // Content
    {
        //m_logInfo.logInfo("Text sent failed.");
        return false;
    }

    if (!SendFileBody()) //Att
    {
        return false;
    }

    if (!SendEnd()) // End
    {
        return false;
    }

    return true;
}

void CSendMail::setServerName(const std::string server_name) // smtp host
{
    m_ServerName = server_name;
}

void CSendMail::setUserName(const std::string user_name) // user
{
    m_UserName = user_name;
}

void CSendMail::setUserPwd(const std::string user_pwd) // pass
{
    m_UserPwd = user_pwd;
}

void CSendMail::setSenderName(const std::string sender_name) // sendername
{
    m_SenderName = sender_name;
}

void CSendMail::setSenderAddress(const std::string sender_addr) // mail from
{
    m_SenderAddr = sender_addr;
}

void CSendMail::addReceiver(const std::string name, const std::string address)
{
    m_Receivers.insert(RECEIVERS::value_type(name, address));
}

void CSendMail::setReceiver(const std::string name, const std::string address)
{
    m_Receivers.clear();
    m_Receivers.insert(RECEIVERS::value_type(name, address));
}

void CSendMail::clearReceiver()
{
    m_Receivers.clear();
}

void CSendMail::AddFilePath(std::string szFilePath) //att
{
    for (std::list<std::string>::iterator itrList = m_FilePathList.begin(); itrList != m_FilePathList.end(); ++itrList) {
        if (itrList->compare(szFilePath) == 0) {
            return;
        }
    }
    m_FilePathList.push_back(szFilePath);
}

void CSendMail::DeleteFilePath(std::string szFilePath) // del
{
    for (std::list<std::string>::iterator itrList = m_FilePathList.begin(); itrList != m_FilePathList.end();) {
        if (itrList->compare(szFilePath) == 0) {
            itrList = m_FilePathList.erase(itrList);
        } else {
            itrList++;
        }
    }
}

void CSendMail::DeleteAllPath(void)
{
    m_FilePathList.clear();
}

// `````````````````[Other]`````````````````
string& CSendMail::replace_all(string& str, const string& old_value, const string& new_value)
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

std::string CSendMail::GetFileName(std::string& szFilePath)
{
    replace_all(szFilePath, "/", "\\");
    string szFileName = szFilePath.substr(szFilePath.rfind("\\") + 1, szFilePath.length());
    return szFileName;
}

std::string CSendMail::GetFileData(std::string szFilePath)
{
    std::string szBuffer;
    if (szFilePath.empty()) {
        m_logInfo.logInfo("[SendFileBody]Error:Empty Path.");
        return szBuffer;
    }

    ifstream ifFile(szFilePath.c_str(), ios::binary | ios::in);
    if (!ifFile) {
        m_logInfo.logInfo("[SendFileBody]Error:Path Error.");
        return szBuffer;
    }
    ifFile.seekg(0, ios::beg);
    std::ostringstream tmp;
    tmp << ifFile.rdbuf();
    szBuffer = tmp.str();
    ifFile.close();

    return szBuffer;
}

std::string CSendMail::Base64Encode(std::string in_str)
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

int CSendMail::sendRequest(const std::string content, bool bout)
{
    int len_s = send(_socket, content.c_str(), content.length(), 0);
    if (len_s < 0) {
        m_logInfo.logInfo("[ERROR]SEND:%s", content.c_str());
        return false;
    }

    // m_logInfo.logInfo("[INFO]SEND:%s", content.c_str());

    return len_s;
}

bool CSendMail::rcvResponse(const std::string expected_response)
{
    int recv_bytes = 0;
    char response_buffer[MAX_BUFFER_SIZE];
    if ((recv_bytes = recv(_socket, response_buffer, MAX_BUFFER_SIZE, 0)) < 0) {
        m_logInfo.logInfo("[ERROR]RECV:%s", expected_response.c_str());
        return false;
    }

    std::string response(response_buffer, recv_bytes);
    m_logInfo.logInfo("[INFO]RECV(%s):%s", expected_response.c_str(), response.c_str());
    if (response.substr(0, 3) != expected_response) {
        return false;
    }
    return true;
}

std::string CSendMail::prepareDate()
{
    char date_string[MAX_BUFFER_SIZE];

    time_t seconds;
    time(&seconds);
    strftime(date_string, MAX_BUFFER_SIZE,
        "%a, %d %b %y %H:%M:%S +0800",
        localtime(&seconds)); // +0800 maybe hard code

    return date_string;
}

// `````````````````[Utils]`````````````````
bool CSendMail::CReateSocket()
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
    servaddr.sin_port = htons(SERVICE_PORT); //发邮件一般都是25端口

    struct hostent* hp = gethostbyname(m_ServerName.c_str()); //使用名称
    if (hp == NULL) {
        DWORD dwErrCode = GetLastError();
        return false;
    }
    servaddr.sin_addr.s_addr = *(int*)(*hp->h_addr_list);

    int ret = connect(_socket, (sockaddr*)&servaddr, sizeof(servaddr)); //建立连接
    if (ret == SOCKET_ERROR) {
        DWORD dwErr = GetLastError();
        return false;
    }
    if (!rcvResponse("220"))
        return false;
    return true;
}

bool CSendMail::Logon()
{
    char local_host[MAX_BUFFER_SIZE];
    if (gethostname(local_host, MAX_BUFFER_SIZE) != 0) {
        m_logInfo.logInfo("Get local host name error!");
        return false;
    }

    std::string msg;

    msg = "HELO ";
    //msg += std::string(local_host) + "\r\n";
    msg += "smtp.163.com\r\n";
    sendRequest(msg);
    if (!rcvResponse("250")) {
        return false;
    }

    msg = "AUTH LOGIN\r\n";
    sendRequest(msg);
    if (!rcvResponse("334")) {
        return false;
    }

    msg = Base64Encode(m_UserName) + "\r\n";
    sendRequest(msg);
    if (!rcvResponse("334")) {
        return false;
    }

    msg = Base64Encode(m_UserPwd) + "\r\n";
    sendRequest(msg);
    if (!rcvResponse("235")) {
        return false;
    }

    return true;
}

bool CSendMail::SendHead()
{
    std::string msg;

    msg = "MAIL FROM:<";
    msg += m_SenderAddr + ">\r\n";
    sendRequest(msg);
    if (!rcvResponse("250")) {
        m_logInfo.logInfo("Address Error:%s", m_SenderAddr.c_str());
        return false;
    }

    for (RECEIVERS::iterator itrRec = m_Receivers.begin(); itrRec != m_Receivers.end(); itrRec++) {
        msg = "RCPT TO:<";
        msg += itrRec->second + ">\r\n";
        sendRequest(msg);
        if (!rcvResponse("250")) {
            return false;
        }
    }

    msg = "DATA\r\n";
    sendRequest(msg);
    if (!rcvResponse("354")) {
        return false;
    }

    msg = "From:\"" + m_SenderName + "\"<" + m_SenderAddr + ">\r\n";

    msg += "To: ";
    for (RECEIVERS::iterator itrRec = m_Receivers.begin(); itrRec != m_Receivers.end(); itrRec++) {
        std::string szRecv;
        szRecv = "\"" + itrRec->first + "\"<" + itrRec->second + ">, ";
        msg += szRecv;
    }
    msg += "\r\n";

    msg += "Date: ";
    msg += prepareDate() + "\r\n";

    msg += "Subject: ";
    msg += m_MailTitle + "\r\n";

    msg += "X-Mailer: Psycho WebMail Client version 1.0\r\n";

    msg += "MIME-Version: 1.0\r\n";
    msg += "Content-type: multipart/mixed;  boundary=\"----=_BIT2019CommonBoundary\"\r\n\r\n";

    msg += "\r\n";
    //Content-Type: multipart/alternative;
    //    boundary="----=_Part_234289_1540052091.1547034190006"
    // msg+="Content-Type: multipart/alternative;\r\n\tboundary=\"----=_BIT2019CommonBoundaryII\"\r\n\r\n";
    // cout << msg << endl;
    sendRequest(msg);
    // sendRequest(".");

    return true;
}

bool CSendMail::SendTextBody()
{
    std::string msg;
    char *ptf_en, *ptf_de;
    msg = "------=_BIT2019CommonBoundary\r\nContent-Type: text/plain;\r\n  charset=\"gb2312\"\r\n\r\n";

    char* temp = const_cast<char*>(m_TextBody.c_str());

    ptf_en = my_encrypt(temp, PUBLICKEY);

    m_TextBody = ptf_en;
    char* b64en = Base64Encode(ptf_en, strlen(ptf_en), false);
    string b64en2;
    b64en2 = b64en;

    msg += b64en2;
    msg += "\r\n\r\n";
    //    msg += "------=_BIT2019CommonBoundary--";
    //    msg += "\r\n\r\n";

    // cout << msg << endl;
    int len_s = sendRequest(msg);

    if (len_s != msg.length()) {
        m_logInfo.logInfo("Error in Sending Message(%d):Real Length(%d)", msg.length(), len_s);
        return false;
    }

    return true;
}

bool CSendMail::SendFileBody()
{
    std::string msg;
    for (std::list<std::string>::iterator itrList = m_FilePathList.begin(); itrList != m_FilePathList.end(); itrList++) {
        std::string filePath = *itrList;
        std::string fileName = GetFileName(filePath);
        std::string szContent = GetFileData(filePath);

        msg = "------=_BIT2019CommonBoundary\r\nContent-Type: application/octet-stream;  name=\"";
        msg += fileName;
        msg += "\"\r\nContent-Transfer-Encoding: base64\r\nContent-Disposition: attachment;  filename=\"";
        msg += fileName;
        msg += "\"\r\n\r\n";
        sendRequest(msg, true);

        int npos = 0, len = szContent.length();
        while (npos < len) {
            std::string szBuffer = Base64Encode(szContent.substr(npos, min(len - npos, 3000)));
            szBuffer += "\r\n";
            // cout << szBuffer << endl;
            sendRequest(szBuffer);
            npos += min(len - npos, 3000);
        }
    }

    return true;
}

bool CSendMail::SendEnd()
{
    std::string msg;

    msg = "------=_BIT2019CommonBoundary--\r\n.\r\n";
    sendRequest(msg, true);

    msg = "QUIT\r\n";
    sendRequest(msg, true);
    if (!rcvResponse("221")) {
        closesocket(_socket);
        WSACleanup();
        return true;
    }
    return false;
}

//en
char* my_encrypt(char* str, char* path_key)
{
    char* p_en = NULL;
    RSA* p_rsa = NULL;
    FILE* file = NULL;

    int rsa_len = 0; //flen为源文件长度， rsa_len为秘钥长度

    if ((file = fopen(path_key, "rb")) == NULL) {
        perror("fopen() error");
        goto End;
    }

    //get pubkey
    if ((p_rsa = PEM_read_RSA_PUBKEY(file, NULL, NULL, NULL)) == NULL) {
        ERR_print_errors_fp(stdout);
        goto End;
    }

    //3.keylen
    rsa_len = RSA_size(p_rsa);

    //4.encryptedlen
    p_en = (char*)malloc(rsa_len + 1);
    if (!p_en) {
        perror("malloc() error");
        goto End;
    }
    memset(p_en, 0, rsa_len + 1);

    //5.encrypt
    if (RSA_public_encrypt(rsa_len, (unsigned char*)str, (unsigned char*)p_en, p_rsa, RSA_NO_PADDING) < 0) {
        perror("RSA_public_encrypt() error");
        goto End;
    }

End:

    //6.release
    if (p_rsa)
        RSA_free(p_rsa);
    if (file)
        fclose(file);

    return p_en;
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

char* Base64Encode(const char* input, int length, bool with_new_line)
{
    BIO* bmem = NULL;
    BIO* b64 = NULL;
    BUF_MEM* bptr = NULL;

    b64 = BIO_new(BIO_f_base64());
    if (!with_new_line) {
        BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    }
    bmem = BIO_new(BIO_s_mem());
    b64 = BIO_push(b64, bmem);
    BIO_write(b64, input, length);
    BIO_flush(b64);
    BIO_get_mem_ptr(b64, &bptr);

    char* buff = (char*)malloc(bptr->length + 1);
    memcpy(buff, bptr->data, bptr->length);
    buff[bptr->length] = 0;

    BIO_free_all(b64);

    return buff;
}

char* Base64Encode(const char* input, int length, bool with_new_line)
{
    BIO* bmem = NULL;
    BIO* b64 = NULL;
    BUF_MEM* bptr = NULL;

    b64 = BIO_new(BIO_f_base64());
    if (!with_new_line) {
        BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    }
    bmem = BIO_new(BIO_s_mem());
    b64 = BIO_push(b64, bmem);
    BIO_write(b64, input, length);
    BIO_flush(b64);
    BIO_get_mem_ptr(b64, &bptr);

    char* buff = (char*)malloc(bptr->length + 1);
    memcpy(buff, bptr->data, bptr->length);
    buff[bptr->length] = 0;

    BIO_free_all(b64);

    return buff;
}