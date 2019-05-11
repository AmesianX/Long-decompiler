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
/// \file sleigh_arch.hh
/// \brief Architecture objects that use a Translate object derived from Sleigh

#ifndef __SLEIGH_ARCH__
#define __SLEIGH_ARCH__

#include "filemanage.hh"
#include "architecture.hh"
#include "sleigh.hh"

namespace GhidraDec {
/// \brief Contents of a \<compiler> tag in a .ldefs file
///
/// This class describes a compiler specification file as referenced by the Sleigh language subsystem.
class CompilerTag {
  std::string name;          ///< (Human readable) name of the compiler
  std::string spec;          ///< cspec file for this compiler
  std::string id;            ///< Unique id for this compiler
public:
  CompilerTag(void) {}	///< Constructor
  void restoreXml(const Element *el);	///< Restore the record from an XML stream
  const std::string &getName(void) const { return name; }	///< Get the human readable name of the spec
  const std::string &getSpec(void) const { return spec; }	///< Get the file-name
  const std::string &getId(void) const { return id; }	///< Get the std::string used as part of \e language \e id
};

/// \brief Contents of the \<language> tag in a .ldefs file
///
/// This class contains meta-data describing a single processor and the std::set of
/// files used to analyze it.  Ghidra requires a compiled SLEIGH specification file
/// (.sla), a processor specification file (.pspec), and a compiler specification file (.cspec)
/// in order to support disassembly/decompilation of a processor.  This class supports
/// a single processor, as described by a single SLEIGH file and processor spec.  Multiple
/// compiler specifications can be given for the single processor.
class LanguageDescription {
  std::string processor;		///< Name of processor
  bool isbigendian;		///< Set to \b true if this processor is \e big-endian
  int4 size;			///< Size of address bus in bits
  std::string variant;		///< Name of processor variant or "default"
  std::string version;		///< Version of the specification
  std::string slafile;		///< Name of .sla file for processor
  std::string processorspec;		///< Name of .pspec file
  std::string id;			///< Unique id for this language
  std::string description;		///< Human readable description of this language
  bool deprecated;		///< Set to \b true if the specification is considered \e deprecated
  std::vector<CompilerTag> compilers;	///< List of compiler specifications compatible with this processor
  std::vector<TruncationTag> truncations;	///< Address space truncations required by this processor
public:
  LanguageDescription(void) {}					///< Constructor
  void restoreXml(const Element *el);				///< Read the XML tag from stream
  const std::string &getProcessor(void) const { return processor; }	///< Get the name of the processor
  bool isBigEndian(void) const { return isbigendian; }		///< Return \b true if the processor is big-endian
  int4 getSize(void) const { return size; }			///< Get the size of the address bus
  const std::string &getVariant(void) const { return variant; }	///< Get the processor variant
  const std::string &getVersion(void) const { return version; }	///< Get the processor version
  const std::string &getSlaFile(void) const { return slafile; }	///< Get filename of the SLEIGH specification
  const std::string &getProcessorSpec(void) const { return processorspec; }	///< Get the filename of the processor specification
  const std::string &getId(void) const { return id; }		///< Get the \e language \e id std::string associated with this processor
  const std::string &getDescription(void) const { return description; }	///< Get a description of the processor
  bool isDeprecated(void) const { return deprecated; }		///< Return \b true if this specification is deprecated
  const CompilerTag &getCompiler(const std::string &nm) const;	///< Get compiler specification of the given name
  int4 numTruncations(void) const { return truncations.size(); }	///< Get the number of truncation records
  const TruncationTag &getTruncation(int4 i) const { return truncations[i]; }	///< Get the i-th truncation record
};

/// \brief An Architecture that uses the decompiler's native SLEIGH translation engine
///
/// Any Architecture derived from \b this knows how to natively read in:
///   - a compiled SLEIGH specification (.sla)
///   - a processor specification file (.pspec), and
///   - a compiler specification file (.cspec)
///
/// Generally a \e language \e id (i.e. x86:LE:64:default) is provided, then this
/// object is able to automatically load in configuration and construct the Translate object.
class SleighArchitecture : public Architecture {
  static Sleigh *last_sleigh;				///< Last Translate object used by a SleighArchitecture
  static int4 last_languageindex;			///< Index of the LanguageDescription associated with the last Translate object
  static std::vector<LanguageDescription> description;	///< List of languages we know about
  int4 languageindex;					///< Index (within LanguageDescription array) of the active language
  std::string filename;					///< Name of active load-image file
  std::string target;					///< The \e language \e id of the active load-image
  static void loadLanguageDescription(const std::string &specfile,std::ostream &errs);
  bool isTranslateReused(void);				///< Test if last Translate object can be reused
protected:
  std::ostream *errorstream;					///< Error stream associated with \b this SleighArchitecture
  // buildLoader must be filled in by derived class
  static void collectSpecFiles(std::ostream &errs);		///< Gather specification files in normal locations
  virtual Translate *buildTranslator(DocumentStorage &store);
  virtual PcodeInjectLibrary *buildPcodeInjectLibrary(void);
  virtual void buildSpecFile(DocumentStorage &store);
  virtual void modifySpaces(Translate *trans);
  virtual void resolveArchitecture(void);
public:
  SleighArchitecture(const std::string &fname,const std::string &targ,std::ostream *estream);	///< Construct given executable file
  const std::string &getFilename(void) const { return filename; }	///< Get the executable filename
  const std::string &getTarget(void) const { return target; }	///< Get the \e language \e id of the active processor
  void saveXmlHeader(std::ostream &s) const;				///< Write out (as XML) basic attributes of the active executable
  void restoreXmlHeader(const Element *el);			///< Restore from XML basic attributes of an executable
  virtual void printMessage(const std::string &message) const { *errorstream << message << std::endl; }
  virtual ~SleighArchitecture(void);
  virtual std::string getDescription(void) const;
  
  static std::string normalizeProcessor(const std::string &nm);		///< Try to recover a \e language \e id processor field
  static std::string normalizeEndian(const std::string &nm);		///< Try to recover a \e language \e id endianess field
  static std::string normalizeSize(const std::string &nm);		///< Try to recover a \e language \e id size field
  static std::string normalizeArchitecture(const std::string &nm);	///< Try to recover a \e language \e id std::string
  static void scanForSleighDirectories(const std::string &rootpath);
  static void shutdown(void);					///< Shutdown this SleighArchitecture and free all resources.
  static FileManage specpaths;					///< Known directories that contain .ldefs files.
};

}
#endif
