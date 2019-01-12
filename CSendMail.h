/*
**CSendMail头文件
**实现邮件的发送功能，支持多个用户接收，支持附件
**program by six_beauty
*/

#pragma once
#include "LogInfo.h"
#include <list>
#include <map>
#include <string>
#include <winsock2.h>

const int MAX_BUFFER_SIZE = 255; //send和recv的缓存buffer的size
const int SERVICE_PORT = 25; // 25 for smtp

typedef std::map<std::string, std::string> RECEIVERS;

//CSendMail类
class CSendMail {
public:
    CSendMail();
    ~CSendMail();
    void setServerName(const std::string server_name);
    void setUserName(const std::string user_name);
    void setUserPwd(const std::string user_pwd);
    void setSenderName(const std::string sender_name);
    void setSenderAddress(const std::string sender_addr);
    void setReceiver(const std::string name, const std::string address);
    void addReceiver(const std::string name, const std::string address);
    void clearReceiver();
    // Attachment
    void AddFilePath(std::string szFilePath);
    void DeleteFilePath(std::string szFilePath);
    void DeleteAllPath();
    // Connect
    bool Connent();
    bool SendMail(const std::string mail_title, const std::string send_content);

private:
    inline std::string& replace_all(string& str, const string& old_value, const string& new_value);
    std::string GetFileName(std::string& szFilePath);
    std::string GetFileData(std::string szFilePath);
    std::string Base64Encode(std::string in_str); 
    std::string prepareDate();
    int sendRequest(const std::string content, bool bout = false); 
    bool rcvResponse(const std::string expected_response); 
    bool CReateSocket(); 
    bool Logon(); 
    bool SendHead(); 
    bool SendTextBody(); 
    bool SendFileBody();
    bool SendEnd();
    SOCKET _socket;
    LogInfo m_logInfo;
    std::string m_ServerName;
    std::string m_UserName;
    std::string m_UserPwd;
    std::string m_SenderName;
    std::string m_SenderAddr;
    std::string m_MailTitle;
    std::string m_TextBody;
    RECEIVERS m_Receivers;
    std::list<std::string> m_FilePathList;
};