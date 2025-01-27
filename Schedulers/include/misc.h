#include <iostream>
#include <filesystem>
#include <vector>
#include <cstring>
#include <sstream>
#include <chrono>

#include "params.h"

bool folderFileExists(std::string folder_path );

char**getExecvArgs( const std::vector<std::string> &args );

std::string numToStr( uint x, uint precision);

uint fileSize(const char* filename);
bool fileHasSubstring( const std::string file_path, const std::string str);

void sleepThread( uint msecs );

double timeElapsedMSecs( std::chrono::time_point<std::chrono::system_clock> t );
double timeDiffSecs(std::chrono::time_point<std::chrono::system_clock> t_large, std::chrono::time_point<std::chrono::system_clock> t_small);


int supress_stdout();
void resume_stdout(int fd);

uint countFilesInDirectory(const std::string &dir_path);

std::vector<std::string> split(const std::string& s, char delimiter);

void copyFiles(const fs::path& source_dir, const fs::path& dest_dir);

uint countFilesInFolder(const std::string& folder_path);