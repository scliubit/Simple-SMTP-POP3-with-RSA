#pragma once
#include "LogInfopop.h"
#include <list>
#include <map>
#include <string>
#include <winsock2.h>

const int POP_MAX_BUFFER_SIZE = 32000; //send和recv的缓存buffer的size
const int POP_SERVICE_PORT = 110; // 110 for pop3

typedef std::map<std::string, std::string> RECEIVERS;

//CRecvMail
class CRecvMail {
public:
    CRecvMail();
    ~CRecvMail();
    void setServerName(const std::string server_name); // pop3 server
    void setUserName(const std::string user_name); // user
    void setUserPwd(const std::string user_pwd); // auth pass
    bool Connent();

private:
    inline std::string& replace_all(string& str, const string& old_value, const string& new_value); //replace c string
    std::string Base64Encode(std::string in_str); //string -> Base64
    std::string prepareDate();
    int sendRequest(const std::string content, bool bout = false);
    bool rcvResponse(const std::string expected_response, bool flag);
    bool CReateSocket(); 
    bool Logon(); 
    bool listMailBox();
    bool getMail(std::string mailnum);
    // internal var
    SOCKET _socket;
    PopLogInfo m_logInfo;
    std::string m_ServerName;
    std::string m_UserName;
    std::string m_UserPwd;
    std::string m_SenderName; 
    std::string m_SenderAddr;
    std::string m_MailTitle;
    std::string m_TextBody;
};
