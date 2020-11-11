#ifndef __SYLAR_LOG_H__
#define __SYLAR_LOG_H__

#include <string>
#include <stdint.h>
#include <memory>
#include <list>
#include <sstream>
#include <fstream>
#include <vector>
#include <stdarg.h>
#include <map>
#include "util.h"
#include "singleton.h"

//宏定义日志调用方法
#define SYLAR_LOG_LEVEL(logger, level)                                              \
    if(logger->getLevel() <= level)                                                 \
        sylar::LogEventWrap(sylar::LogEvent::ptr(new sylar::LogEvent(logger, level, \
                        __FILE__, __LINE__, 0, sylar::GetThreadId(),                \
                sylar::GetFiberId(), time(0)))).getSS()

#define SYLAR_LOG_DEBUG(logger) SYLAR_LOG_LEVEL(logger,sylar::LogLevel::DEBUG)
#define SYLAR_LOG_INFO(logger) SYLAR_LOG_LEVEL(logger,sylar::LogLevel::INFO)
#define SYLAR_LOG_WARN(logger) SYLAR_LOG_LEVEL(logger,sylar::LogLevel::WARN)
#define SYLAR_LOG_ERROR(logger) SYLAR_LOG_LEVEL(logger,sylar::LogLevel::ERROR)
#define SYLAR_LOG_FATAL(logger) SYLAR_LOG_LEVEL(logger,sylar::LogLevel::FATAL)

#define SYLAR_LOG_FMT_LEVEL(logger, level, fmt, ...)                                \
    if(logger->getLevel() <= level)                                                 \
        sylar::LogEventWrap(sylar::LogEvent::ptr(new sylar::LogEvent(logger, level, \
                        __FILE__, __LINE__, 0, sylar::GetThreadId(),                \
                sylar::GetFiberId(), time(0)))).getEvent()->format(fmt, __VA_ARGS__)

#define SYLAR_LOG_FMT_DEBUG(logger, fmt, ...) SYLAR_LOG_FMT_LEVEL(logger, sylar::LogLevel::DEBUG, fmt, __VA_ARGS__)
#define SYLAR_LOG_FMT_INFO(logger, fmt, ...)  SYLAR_LOG_FMT_LEVEL(logger, sylar::LogLevel::INFO, fmt, __VA_ARGS__)
#define SYLAR_LOG_FMT_WARN(logger, fmt, ...)  SYLAR_LOG_FMT_LEVEL(logger, sylar::LogLevel::WARN, fmt, __VA_ARGS__)
#define SYLAR_LOG_FMT_ERROR(logger, fmt, ...) SYLAR_LOG_FMT_LEVEL(logger, sylar::LogLevel::ERROR, fmt, __VA_ARGS__)
#define SYLAR_LOG_FMT_FATAL(logger, fmt, ...) SYLAR_LOG_FMT_LEVEL(logger, sylar::LogLevel::FATAL, fmt, __VA_ARGS__)

#define SYLAR_LOG_ROOT() sylar::LoggerMgr::GetInstance()->getRoot()
#define SYLAR_LOG_NAME(name) sylar::LoggerMgr::GetInstance()->getLogger(name)

namespace sylar{

class Logger;


//日志级别
class LogLevel{
    public:
        enum Level{
            UNKNOW = 0,
            DEBUG = 1,
            INFO = 2,
            WARN = 3,
            ERROR = 4,
            FATAL = 5
        };
        
        static const char* ToString(LogLevel::Level);    
};


//日志信息类
class LogEvent{
    public:
        typedef std::shared_ptr<LogEvent> ptr;

        LogEvent(std::shared_ptr<Logger> logger, LogLevel::Level level
                ,const char* file, int32_t m_line, uint32_t elapse
                , uint32_t thread_id, uint32_t fiber_id, uint64_t time);
                
        const char* getFile() const{return m_file;}
        int32_t getLine() const {return m_line;}
        uint32_t getElapse() const {return m_elapse;}
        uint32_t getThreadid() const {return m_threadid;}
        uint64_t getFiberid() const {return m_fiberid;}
        uint64_t getTime() const {return m_time;}

        std::string getContent() const { return m_ss.str();}
        
        std::shared_ptr<Logger> getLogger() const { return m_logger;}
        LogLevel::Level getLevel() const { return m_level;}
        std::stringstream& getSS() { return m_ss;}
        
        void format(const char* fmt, ...);
        void format(const char* fmt, va_list al);

    private:
        //文件名称
        const char* m_file = nullptr;
        //行号
        int32_t m_line = 0;
        //程序运行到现在的时间(毫秒)
        uint32_t m_elapse = 0;
        //线程号
        uint32_t m_threadid = 0;
        //协程号
        uint32_t m_fiberid = 0;
        //当前时间戳
        uint64_t m_time = 0;
        //输出内容
        std::string m_content;

        std::stringstream m_ss;

        std::shared_ptr<Logger> m_logger;
        LogLevel::Level m_level;
};

class LogEventWrap {
public:
    LogEventWrap(LogEvent::ptr e);
    ~LogEventWrap();
    LogEvent::ptr getEvent() const { return m_event;}
    std::stringstream& getSS();
private:
    LogEvent::ptr m_event;
};


//日志格式器
class LogFormatter{
    public:
        LogFormatter(const std::string& pattern);
        void init();
        typedef std::shared_ptr<LogFormatter> ptr;
        std::string format(std::shared_ptr<Logger>,LogLevel::Level, LogEvent::ptr);
    public:
        class FormatItem{
        public:
            typedef std::shared_ptr<FormatItem> ptr;
            virtual ~FormatItem(){}
            virtual void format(std::ostream&,std::shared_ptr<Logger>,LogLevel::Level,LogEvent::ptr)=0;
        };    
    private:
        std::string m_pattern;
        std::vector<FormatItem::ptr> m_items;
};

//日志输出器
class LogAppender{
    public:
        typedef std::shared_ptr<LogAppender> ptr;
        virtual ~LogAppender(){}
        virtual void log(std::shared_ptr<Logger>,LogLevel::Level,LogEvent::ptr) = 0;
        void setFormatter(LogFormatter::ptr val) { m_formatter = val;}
        LogFormatter::ptr getFormatter() const { return m_formatter;}

        LogLevel::Level getLevel() const { return m_level;}
        void setLevel(LogLevel::Level val) { m_level = val;}
    protected:
        LogFormatter::ptr m_formatter;
        LogLevel::Level m_level = LogLevel::DEBUG;
};

//日志输出器
class Logger : public std::enable_shared_from_this<Logger> {
    public:
        typedef std::shared_ptr<Logger> ptr;
        Logger(const std::string& name = "root");
        //日志输出
        void log(LogLevel::Level,LogEvent::ptr);
        
        void debug(LogEvent::ptr);
        void info(LogEvent::ptr);
        void error(LogEvent::ptr);
        void warn(LogEvent::ptr);
        void fatal(LogEvent::ptr);
        
        void addAppender(LogAppender::ptr);
        void delAppender(LogAppender::ptr);

        LogLevel::Level getLevel() const {return m_level;};
        void setLevel(LogLevel::Level val){m_level = val;};
        
        const std::string getName() const {return m_name;}
    
    private:
        std::string m_name;
        LogLevel::Level m_level; 
        std::list<LogAppender::ptr> m_appenders;
        LogFormatter::ptr m_formatter;
};    

//输出到控制台的输出器
class StdoutLogAppender:public LogAppender{
    public:
        typedef std::shared_ptr<StdoutLogAppender> ptr;
        void log(Logger::ptr logger,LogLevel::Level,LogEvent::ptr) override;
};

//输出到文件的输出器
class FileoutLogAppender:public LogAppender{
    public:
        typedef std::shared_ptr<FileoutLogAppender> ptr;
        FileoutLogAppender(const std::string& filename);
        void log(Logger::ptr logger,LogLevel::Level,LogEvent::ptr) override;
        bool reopen();
    private:    
        std::string m_filename;
        std::ofstream m_filestream;
};

class LoggerManager {
public:
    LoggerManager();
    Logger::ptr getLogger(const std::string& name);

    void init();
    Logger::ptr getRoot() const { return m_root;}
private:
    std::map<std::string, Logger::ptr> m_loggers;
    Logger::ptr m_root;
};

typedef sylar::Singleton<LoggerManager> LoggerMgr;

}

#endif

