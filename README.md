
Some Codes are from the Internet.

Bugs **do** exists.


# Simple-SMTP-POP3-with-RSA
北京理工大学 小学期课程设计.
在VS2015下编译通过

Add a ```demo.cpp``` below and enjoy.

```C++
#include "CRecvMail.h"
#include "CSendMail.h"
#include "iostream"
using namespace std;

void smtp()
{
    CSendMail sMailer;

    sMailer.setServerName("smtp.163.com"); // smtp server
    sMailer.setUserName("Username"); // username, e.g. usaername( <optional> @mail.com)
    sMailer.setUserPwd("password"); // password
    sMailer.setSenderName("Sender"); // Sender Name
    sMailer.setSenderAddress("SenderAddr@163.com"); // Sender Addr

    sMailer.setReceiver("Recever", "ReceverAddr"); // Recever
    // sMailer.addReceiver("AnotherRecever", "Recever2Addr@163.com");

    sMailer.AddFilePath("ATT.txt"); // Add Attachments.
    // Send
    if (sMailer.Connent()) // Connect
    {
        if (sMailer.SendMail("CMailSender:Subject", "Hello World")) // Subject and Content
            cout << "Complete!" << endl;
    }
}
void pop3()
{
    CRecvMail rMailer;
    rMailer.setServerName("pop3.163.com"); // pop3 server
    rMailer.setUserName("Username");
    rMailer.setUserPwd("password");
    rMailer.Connent();
}
int main()
{
    int selection;
    cout << "select smtp(0) or pop3(1) or exit(others)" << endl;
    cin >> selection;
    if (selection == 1) {
        pop3();
    } else if (selection == 0) {
        smtp();
    } else {
        return 0;
    }
    main();
    return 0;
}
```

env:
 - OpenSSL

 - Winsock
