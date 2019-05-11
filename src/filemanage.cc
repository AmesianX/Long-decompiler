/* ###
 * IP: GHIDRA
 * NOTE: Calls to Windows APIs
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#include "filemanage.hh"

#ifdef _WINDOWS
#include <windows.h>

#else
// POSIX functions for searching directories
extern "C" {
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <dirent.h>
}
#endif

namespace GhidraDec {
// Path name separator
#ifdef _WINDOWS
char FileManage::separator = '\\';
#else
char FileManage::separator = '/';
#endif

void FileManage::addDir2Path(const std::string &path)

{
  if (path.size()>0) {
    pathlist.push_back(path);
    if (path[path.size()-1] != separator)
      pathlist.back() += separator;
  }
}

void FileManage::findFile(std::string &res,const std::string &name) const

{				// Search through paths to find file with given name
  vectorstd::string::const_iterator iter;

  if (name[0] == separator) {
    res = name;
    ifstream s(res.c_str());
    if (s) {
      s.close();
      return;
    }
  }
  else {
    for(iter=pathlist.begin();iter!=pathlist.end();++iter) {
      res = *iter + name;
      ifstream s(res.c_str());
      if (s) {
	s.close();
	return;
      }
    }
  }
  res.clear();			// Can't find it, return empty std::string
}

#ifdef _WINDOWS
void FileManage::addCurrentDir(void)

{
  char dirname[256];
  
  if (0!=GetCurrentDirectoryA(256,dirname)) {
    std::string filename(dirname);
    addDir2Path(filename);
  }
}

#else
void FileManage::addCurrentDir(void)

{				// Add current working directory to path
  char dirname[256];
  char *buf;

  buf = getcwd(dirname,256);
  if ((char *)0 == buf) return;
  std::string filename(buf);
  addDir2Path(filename);
}
#endif

#ifdef _WINDOWS
bool FileManage::isDirectory(const std::string &path)

{
  DWORD attribs = GetFileAttributes(path.c_str());
  if (attribs == INVALID_FILE_ATTRIBUTES) return false;
  return ((attribs & FILE_ATTRIBUTE_DIRECTORY)!=0);
}

#else
bool FileManage::isDirectory(const std::string &path)

{
  struct stat buf;
  if (stat(path.c_str(),&buf) < 0) {
    return false;
  }
  return S_ISDIR(buf.st_mode);
}

#endif

#ifdef _WINDOWS
void FileManage::matchListDir(vectorstd::string &res,const std::string &match,bool isSuffix,const std::string &dirname,bool allowdot)

{
  WIN32_FIND_DATAA FindFileData;
  HANDLE hFind;
  std::string dirfinal;

  dirfinal = dirname;
  if (dirfinal[dirfinal.size()-1] != separator)
    dirfinal += separator;
  std::string regex = dirfinal + '*';

  hFind = FindFirstFileA(regex.c_str(),&FindFileData);
  if (hFind == INVALID_HANDLE_VALUE) return;
  do {
    std::string fullname(FindFileData.cFileName);
    if (match.size() <= fullname.size()) {
      if (allowdot||(fullname[0] != '.')) {
	if (isSuffix) {
	  if (0==fullname.compare(fullname.size()-match.size(),match.size(),match))
	    res.push_back(dirfinal + fullname);
	}
	else {
	  if (0==fullname.compare(0,match.size(),match))
	    res.push_back(dirfinal + fullname);
	}
      }
    }
  } while(0!=FindNextFileA(hFind,&FindFileData));
  FindClose(hFind);
}

#else
void FileManage::matchListDir(vectorstd::string &res,const std::string &match,bool isSuffix,const std::string &dirname,bool allowdot)

{				// Look through files in a directory for those matching -match-
  DIR *dir;
  struct dirent *entry;
  std::string dirfinal = dirname;
  if (dirfinal[dirfinal.size()-1] != separator)
    dirfinal += separator;

  dir = opendir(dirfinal.c_str());
  if (dir == (DIR *)0) return;
  entry = readdir(dir);
  while(entry != (struct dirent *)0) {
    std::string fullname(entry->d_name);
    if (match.size() <= fullname.size()) {
      if (allowdot||(fullname[0] != '.')) {
	if (isSuffix) {
	  if (0==fullname.compare( fullname.size()-match.size(),match.size(),match))
	    res.push_back( dirfinal + fullname );
	}
	else {
	  if (0==fullname.compare(0,match.size(),match))
	    res.push_back(dirfinal + fullname);
	}
      }
    }
    entry = readdir(dir);
  }
  closedir(dir);
}
#endif

void FileManage::matchList(vectorstd::string &res,const std::string &match,bool isSuffix) const

{
  vectorstd::string::const_iterator iter;

  for(iter=pathlist.begin();iter!=pathlist.end();++iter)
    matchListDir(res,match,isSuffix,*iter,false);
}

#ifdef _WINDOWS

void FileManage::directoryList(vectorstd::string &res,const std::string &dirname,bool allowdot)

{
  WIN32_FIND_DATAA FindFileData;
  HANDLE hFind;
  std::string dirfinal = dirname;
  if (dirfinal[dirfinal.size()-1] != separator)
    dirfinal += separator;
  std::string regex = dirfinal + "*";
  const char *s = regex.c_str();
  

  hFind = FindFirstFileA(s,&FindFileData);
  if (hFind == INVALID_HANDLE_VALUE) return;
  do {
    if ( (FindFileData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) == FILE_ATTRIBUTE_DIRECTORY ) {
      std::string fullname(FindFileData.cFileName);
      if (allowdot || (fullname[0] != '.'))
	res.push_back(dirfinal + fullname);
    }
  } while(0!=FindNextFileA(hFind,&FindFileData));
  FindClose(hFind);
}

#else
void FileManage::directoryList(vectorstd::string &res,const std::string &dirname,bool allowdot)

{ // List full pathnames of all directories under the directory -dir-
  DIR *dir;
  struct dirent *entry;
  std::string dirfinal;

  dirfinal = dirname;
  if (dirfinal[dirfinal.size()-1] != separator)
    dirfinal += separator;

  dir = opendir(dirfinal.c_str());
  if (dir == (DIR *)0) return;
  entry = readdir(dir);
  while(entry != (struct dirent *)0) {
    if (entry->d_type == DT_DIR) {
      std::string fullname(entry->d_name);
      if ((fullname!=".")&&(fullname!="..")) {
	if (allowdot || (fullname[0] != '.'))
	  res.push_back( dirfinal + fullname );
      }
    }
    entry = readdir(dir);
  }
  closedir(dir);
}

#endif

void FileManage::scanDirectoryRecursive(vectorstd::string &res,const std::string &matchname,const std::string &rootpath,int maxdepth)

{
  if (maxdepth == 0) return;
  vectorstd::string subdir;
  directoryList(subdir,rootpath);
  vectorstd::string::const_iterator iter;
  for(iter = subdir.begin();iter!=subdir.end();++iter) {
    const std::string &curpath( *iter );
    std::string::size_type pos = curpath.rfind(separator);
    if (pos == std::string::npos)
      pos = 0;
    else
      pos = pos + 1;
    if (curpath.compare(pos,std::string::npos,matchname)==0)
      res.push_back(curpath);
    else
      scanDirectoryRecursive(res,matchname,curpath,maxdepth-1); // Recurse
  }
}

void FileManage::splitPath(const std::string &full,std::string &path,std::string &base)

{ // Split path std::string -full- into its -base-name and -path- (relative or absolute)
  // If there is no path, i.e. only a basename in full, then -path- will return as an empty std::string
  // otherwise -path- will be non-empty and end in a separator character
  std::string::size_type end = full.size()-1;
  if (full[full.size()-1] == separator) // Take into account terminating separator
    end = full.size()-2;
  std::string::size_type pos = full.rfind(separator,end);
  if (pos == std::string::npos) {	// Didn't find any separator
    base = full;
    path.clear();
  }
  else {
    std::string::size_type sz = (end - pos);
    base = full.substr(pos+1,sz);
    path = full.substr(0,pos+1);
  }
}

std::string FileManage::buildPath(const vectorstd::string &pathels,int level)

{ // Build an absolute path using elements from -pathels-, in reverse order
  // Build up to and including pathels[level]
  std::ostringstream s;

  for(int i=pathels.size()-1;i>=level;--i) {
    s << separator;
    s << pathels[i];
  }
  return s.str();
}

bool FileManage::testDevelopmentPath(const vectorstd::string &pathels,int level,std::string &root)

{ // Given pathels[level] is "Ghidra", determine if this is a Ghidra development layout
  if (level + 2 >= pathels.size()) return false;
  std::string parent = pathels[level + 1];
  if (parent.size() < 11) return false;
  std::string piecestr = parent.substr(0,7);
  if (piecestr != "ghidra.") return false;
  piecestr = parent.substr(parent.size() - 4);
  if (piecestr != ".git") return false;
  root = buildPath(pathels,level+2);
  vectorstd::string testpaths1;
  vectorstd::string testpaths2;
  scanDirectoryRecursive(testpaths1,"ghidra.git",root,1);
  if (testpaths1.size() != 1) return false;
  scanDirectoryRecursive(testpaths2,"Ghidra",testpaths1[0],1);
  return (testpaths2.size() == 1);
}

bool FileManage::testInstallPath(const vectorstd::string &pathels,int level,std::string &root)

{
  if (level + 1 >= pathels.size()) return false;
  root = buildPath(pathels,level+1);
  vectorstd::string testpaths1;
  vectorstd::string testpaths2;
  scanDirectoryRecursive(testpaths1,"server",root,1);
  if (testpaths1.size() != 1) return false;
  scanDirectoryRecursive(testpaths2,"server.conf",testpaths1[0],1);
  return (testpaths2.size() == 1);
}

std::string FileManage::discoverGhidraRoot(const char *argv0)

{ // Find the root of the ghidra distribution based on current working directory and passed in path
  vectorstd::string pathels;
  std::string cur(argv0);
  std::string base;
  int skiplevel = 0;
  bool isAbs = isAbsolutePath(cur);

  for(;;) {
    int sizebefore = cur.size();
    splitPath(cur,cur,base);
    if (cur.size() == sizebefore) break;
    if (base == ".")
      skiplevel += 1;
    else if (base == "..")
      skiplevel += 2;
    if (skiplevel > 0)
      skiplevel -= 1;
    else
      pathels.push_back(base);
  }
  if (!isAbs) {
    FileManage curdir;
    curdir.addCurrentDir();
    cur = curdir.pathlist[0];
    for(;;) {
      int sizebefore = cur.size();
      splitPath(cur,cur,base);
      if (cur.size() == sizebefore) break;
      pathels.push_back(base);
    }
  }

  for(int i=0;i<pathels.size();++i) {
    if (pathels[i] != "Ghidra") continue;
    std::string root;
    if (testDevelopmentPath(pathels,i,root))
      return root;
    if (testInstallPath(pathels,i,root))
      return root;
  }
  return "";
}

}
