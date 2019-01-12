#include <iostream>
#include <stdarg.h>

using namespace std;

const int POP_BUF_SIZE = 32000;
class PopLogInfo {
public:
    PopLogInfo(){};
    ~PopLogInfo(){};

    void logInfo(char* szFormat, ...)
    {
        char szBuf[POP_BUF_SIZE] = {};
        va_list args;
        va_start(args, szFormat);
        _vsnprintf(szBuf, POP_BUF_SIZE, szFormat, args);
        va_end(args);
        std::cout << szBuf << endl;
        return;
    }
};