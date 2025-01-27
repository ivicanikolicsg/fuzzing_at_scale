#include <fstream>
#include <thread>
#include <chrono>
#include <boost/process.hpp>
#include <boost/filesystem.hpp>
#include <cstdlib>
#include <unistd.h>
#include <fcntl.h>
#include "misc.h"


bool folderFileExists(std::string path ) {
    return std::filesystem::exists( std::filesystem::path{path} );
}

// ignore empty strings
char**getExecvArgs( const std::vector<std::string> &args ) {
    char **char_args = new char*[ args.size() + 1 ];
    int pos = 0;
    for( uint i=0; i< args.size(); i++){
        if( args[i].size() > 0 ){
            char_args[pos] = new char[args[i].size() + 1 ];
            strcpy( char_args[pos], args[i].c_str() );
            pos++;
        }
    }
    char_args[ pos ] = NULL;
    return char_args;
}

std::string numToStr( uint x, uint spaces) {
    std::ostringstream oss;
    oss.fill('0');
    oss.width(spaces);
    oss<<x;
    std::string result = oss.str();    
    return result;
}

uint fileSize(const char* filename) {
    std::ifstream in(filename, std::ifstream::ate | std::ifstream::binary);
    auto r = static_cast<int>(in.tellg()); 
    return r >= 0 ? r : 0;
}

bool fileHasSubstring( const std::string file_path, const std::string str){
    std::ifstream file(file_path);
    if( file.is_open() ){
        std::string line;
        while (std::getline(file, line)) {
            if (line.find(str) != std::string::npos)
                return true;
        }
        file.close();
    }
    return false;
} 

void sleepThread( uint msecs ){
    std::this_thread::sleep_for( std::chrono::milliseconds( msecs) );
}

double timeElapsedMSecs( std::chrono::time_point<std::chrono::system_clock> t ) {
    return std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now() - t).count();
}

double timeDiffSecs(std::chrono::time_point<std::chrono::system_clock> t_large, std::chrono::time_point<std::chrono::system_clock> t_small){
    return std::chrono::duration_cast<std::chrono::milliseconds>(t_large - t_small).count()/1000.0;
}

int supress_stdout() {
  fflush(stdout);

  int ret = dup(1);
  int nullfd = open("/dev/null", O_WRONLY);
  dup2(nullfd, 1);
  close(nullfd);

  return ret;
}

void resume_stdout(int fd) {
  fflush(stdout);
  dup2(fd, 1);
  close(fd);
}


uint countFilesInDirectory(const std::string &dir_path) {
    uint file_count = 0;
    if (!std::filesystem::is_directory(dir_path)) 
        return file_count;
    for (const auto &entry : std::filesystem::directory_iterator(dir_path)) {
        if (entry.is_regular_file()) {
            file_count++;
        }
    }
    return file_count;
}

std::vector<std::string> split(const std::string& s, char delimiter) {
    std::vector<std::string> tokens;
    std::string token;
    std::istringstream tokenStream(s);
    while (getline(tokenStream, token, delimiter)) {
        tokens.push_back(token);
    }
    return tokens;
}

void copyFiles(const fs::path& source_dir, const fs::path& dest_dir) {
    if (!fs::is_directory(source_dir) || !fs::exists(source_dir) || !fs::exists(dest_dir) ) {
        std::cerr << "Error in copyFiles : " << !fs::is_directory(source_dir) << !fs::exists(source_dir) << !fs::exists(dest_dir) << std::endl;
        return;
    }

    for (const auto& entry : fs::directory_iterator(source_dir)) {
        const auto& source_file = entry.path();
        const auto& dest_file = dest_dir / source_file.filename();

        try {
            fs::copy(source_file, dest_file, fs::copy_options::overwrite_existing);
        } catch (const fs::filesystem_error& e) {
            std::cerr << "Error copying file : " << e.what() << '\n';
            continue;
        }
    }
}

uint countFilesInFolder(const std::string& folder_path) {
    uint count = 0;
    if (!fs::exists(folder_path)) 
        return count;
    for (auto& entry : fs::directory_iterator(folder_path)) 
        count += entry.is_regular_file();
    return count;
}



std::string getEnvironmentVariable(const std::string &varName, bool throwIfNotFound) {
    const char *val = std::getenv(varName.c_str());
    if (val == nullptr) { 
        if (throwIfNotFound )
            throw std::runtime_error("Environment variable " + varName + " not found");
        else
            return "";
    }
    return std::string(val);
}