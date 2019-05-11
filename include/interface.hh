/* ###
 * IP: GHIDRA
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
// Very generic command line executor class:   IfaceStatus
// A new class instance derived from IfaceCommand is attached to a command line via registerCom
// i.e.
// IfaceStatus stat(cin,cout);
// stat.registerCom(new IfcQuit(),"quit");
// stat.registerCom(new IfcOpenfileAppend(),"openfile","append");
// stat.mainloop();

// Command line processing is started with mainloop, which prints a
// prompt std::set with setprompt, allows bash style command line editing, including
// command completion and history, and executes the corresponding IfaceCommand.execute callback.
// Command words only have to match enough to disambiguate it from other commands.

// Custom history size can be passed in constructor to IfaceStatus.
// Applications should inherit from base class IfaceStatus in order
// to get custom data into IfaceCommand callbacks and to redefine
// the virtual function execute for custom error handling.

#ifndef __INTERFACE__
#define __INTERFACE__

#include "capability.hh"
#include <string>
#include <map>
#include <algorithm>
#include <fstream>
#include <sstream>
#include <cstdio>

namespace GhidraDec {

struct IfaceError {
  std::string explain;		// Explanatory std::string
  IfaceError(const std::string &s) { explain = s; }
};

struct IfaceParseError : public IfaceError {
  IfaceParseError(const std::string &s) : IfaceError(s) {}
};

struct IfaceExecutionError : public IfaceError {
  IfaceExecutionError(const std::string &s) : IfaceError(s) {}
};

class IfaceStatus;		// Forward declaration

class IfaceData {		// Data specialized for a particular command
public:
  virtual ~IfaceData(void) {}
};

class IfaceCommand {
  std::vector<std::string> com;		// The command
public:
  virtual ~IfaceCommand(void) {}
  virtual void setData(IfaceStatus *root,IfaceData *data)=0;
  virtual void execute(std::istream &s)=0;
  virtual std::string getModule(void) const=0;
  virtual IfaceData *createData(void)=0;
  void addWord(const std::string &temp) { com.push_back(temp); }
  void removeWord(void) { com.pop_back(); }
  const std::string &getCommandWord(int4 i) const { return com[i]; }
  void addWords(const std::vector<std::string> &wordlist);
  int4 numWords(void) const { return com.size(); }
  void commandString(std::string &res) const;
  int4 compare(const IfaceCommand &op2) const;
};

class IfaceCommandDummy : public IfaceCommand {
public:
  virtual void setData(IfaceStatus *root,IfaceData *data) {}
  virtual void execute(std::istream &s) {}
  virtual std::string getModule(void) const { return "dummy"; }
  virtual IfaceData *createData(void) { return (IfaceData *)0; }
};

inline bool compare_ifacecommand(const IfaceCommand *a,const IfaceCommand *b) {
  return (0>a->compare(*b));
}

class IfaceCapability : public CapabilityPoint {
  static std::vector<IfaceCapability *> thelist;
protected:
  std::string name;			// Identifying name for the capability
public:
  const std::string &getName(void) const { return name; }
  virtual void initialize(void);
  virtual void registerCommands(IfaceStatus *status)=0;

  static void registerAllCommands(IfaceStatus *status);
};

class IfaceStatus {
  std::vector<std::istream *> inputstack;
  std::vector<std::string> promptstack;
  std::vector<uint4> flagstack;
  std::string prompt;
  int4 maxhistory;
  int4 curhistory;		// most recent history
  std::vector<std::string> history;
  bool sorted;			// Are commands sorted
  bool inerror;			// -true- if last command did not succeed
  bool errorisdone;		// -true- if any error terminates the process
  void restrict(std::vector<IfaceCommand *>::const_iterator &first,std::vector<IfaceCommand *>::const_iterator &last,std::vector<std::string> &input);
  virtual void readLine(std::string &line) { getline(*sptr,line,'\n'); }
  void saveHistory(const std::string &line);
protected:
  std::istream *sptr;		// Where to get input
  std::vector<IfaceCommand *> comlist; // List of commands
  std::map<std::string,IfaceData *> datamap; // Data associated with particular modules
  int4 expandCom(std::vector<std::string> &expand,std::istream &s,
		std::vector<IfaceCommand *>::const_iterator &first,
		std::vector<IfaceCommand *>::const_iterator &last);
public:
  bool done;
  std::ostream *optr;		// Where to put command line output
  std::ostream *fileoptr;		// Where to put bulk output

  IfaceStatus(const std::string &prmpt,std::istream &is,std::ostream &os,int4 mxhist=10);
  virtual ~IfaceStatus(void);
  void setErrorIsDone(bool val) { errorisdone = val; }
  void pushScript(const std::string &filename,const std::string &newprompt);
  void popScript(void);
  int4 getNumInputStreamSize(void) const { return inputstack.size(); }
  void writePrompt(void) { *optr << prompt; }
  void registerCom(IfaceCommand *fptr, const char *nm1,
		   const char *nm2 = (const char *)0,
		   const char *nm3 = (const char *)0,
		   const char *nm4 = (const char *)0,
		   const char *nm5 = (const char *)0);
  IfaceData *getData(const std::string &nm) const;
  bool runCommand(void);
  void getHistory(std::string &line,int4 i) const;
  int4 getHistorySize(void) const { return history.size(); }
  bool isStreamFinished(void) const { if (done||inerror) return true; return sptr->eof(); }
  bool isInError(void) const { return inerror; }
  void evaluateError(void);
  static void wordsToString(std::string &res,const std::vector<std::string> &std::list);
};

class IfaceBaseCommand : public IfaceCommand {
protected:
  IfaceStatus *status;
public:
  virtual void setData(IfaceStatus *root,IfaceData *data) { status = root; }
  virtual std::string getModule(void) const { return "base"; }
  virtual IfaceData *createData(void) { return (IfaceData *)0; }
};

class IfcQuit : public IfaceBaseCommand {
public:
  virtual void execute(std::istream &s);
};

class IfcHistory : public IfaceBaseCommand {
public:
  virtual void execute(std::istream &s);
};

class IfcOpenfile : public IfaceBaseCommand {
public:
  virtual void execute(std::istream &s);
};

class IfcOpenfileAppend : public IfaceBaseCommand {
public:
  virtual void execute(std::istream &s);
};

class IfcClosefile : public IfaceBaseCommand {
public:
  virtual void execute(std::istream &s);
};

class IfcEcho : public IfaceBaseCommand {
public:
  virtual void execute(std::istream &s);
};

}

#endif
