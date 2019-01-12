#include <iostream>
#include <stdarg.h>

using namespace std;

const int BUF_SIZE = 4096;
//实现输出类
class LogInfo {
public:
    LogInfo(){};
    ~LogInfo(){};

    void logInfo(char* szFormat, ...)
    {
        char szBuf[BUF_SIZE] = {};
        va_list args; //第一步
        va_start(args, szFormat); //第二步
        _vsnprintf(szBuf, BUF_SIZE, szFormat, args); //第三步
        va_end(args); //第四步

        //在这是实现输出方式
        std::cout << szBuf << endl;
        return;
    }
};