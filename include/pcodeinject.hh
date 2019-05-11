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
/// \file pcodeinject.hh
/// \brief Classes for managing \b p-code \b injection.

#ifndef __PCODEINJECT__
#define __PCODEINJECT__

#include "emulateutil.hh"

namespace GhidraDec {

class Architecture;

/// \brief An input or output parameter to a p-code injection payload
///
/// Within the chunk of p-code being injected, this is a placeholder for Varnodes
/// that serve as inputs or outputs to the chunk, which are filled-in in the context
/// of the injection.  For instance, for a \e call-fixup that injects a user-defined
/// p-code op, the input Varnodes would be substituted with the actual input Varnodes
/// to the user-defined op.
class InjectParameter {
  friend class InjectPayload;
  std::string name;		///< Name of the parameter (for use in parsing p-code \e source)
  int4 index;		///< Unique index assigned (for cross referencing associated Varnode in the InjectContext)
  uint4 size;		///< Size of the parameter Varnode in bytes
public:
  InjectParameter(const std::string &nm,uint4 sz) :name(nm) { index = 0; size = sz; }	///< Constructor
  const std::string &getName(void) const { return name; }	///< Get the parameter name
  int4 getIndex(void) const { return index; }		///< Get the assigned index
  uint4 getSize(void) const { return size; }		///< Get the size of the parameter in bytes
};

/// \brief Context needed to emit a p-code injection as a full std::set of p-code operations
///
/// P-code injection works by passing a pre-built template of p-code operations (ConstructTpl)
/// to an emitter (PcodeEmit), which makes the final resolution SLEIGH concepts like \e inst_next to
/// concrete Varnodes. This class contains the context dependent data to resolve:
///   - inst_start  -- the address where the injection occurs
///   - inst_next   -- the address of the instruction following (the instruction being injected)
///   - inst_dest   -- Original destination of CALL being injected
///   - inst_ref    -- Target of reference on injected instruction
///   - \<input>     -- Input Varnode of the injection referenced by name
///   - \<output>    -- Output Varnode of the injection referenced by name
class InjectContext {
public:
  Architecture *glb;			///< Architecture associated with the injection
  Address baseaddr;			///< Address of instruction causing inject
  Address nextaddr;			///< Address of following instruction
  Address calladdr;			///< If the instruction being injected is a call, this is the address being called
  std::vector<VarnodeData> inputlist;	///< Storage location for input parameters
  std::vector<VarnodeData> output;		///< Storage location for output
  virtual ~InjectContext(void) {}	///< Destructor
  virtual void clear(void) { inputlist.clear(); output.clear(); }	///< Release resources (from last injection)

  /// \brief Save \b this context to an XML stream as a \<context> tag
  ///
  /// \param s is the output stream
  virtual void saveXml(std::ostream &s) const=0;
};

/// \brief An active container for a std::set of p-code operations that can be injected into data-flow
///
/// This is an abstract base class. Derived classes manage details of how the p-code
/// is stored.  The methods provide access to the input/output parameter information,
/// and the main injection is performed with inject().
class InjectPayload {
public:
  enum {
    CALLFIXUP_TYPE = 1,		///< Injection that replaces a CALL
    CALLOTHERFIXUP_TYPE = 2,	///< Injection that replaces a user-defined p-code op, CALLOTHER
    CALLMECHANISM_TYPE = 3,	///< Injection to patch up data-flow around the caller/callee boundary
    EXECUTABLEPCODE_TYPE = 4	///< Injection running as a stand-alone p-code script
  };
protected:
  std::string name;			///< Formal name of the payload
  int4 type;			///< Type of this payload: CALLFIXUP_TYPE, CALLOTHERFIXUP_TYPE, etc.
  bool dynamic;			///< True if the injection is generated dynamically
  int4 paramshift;		///< Number of parameters shifted in the original call
  std::vector<InjectParameter> inputlist;		///< List of input parameters to this payload
  std::vector<InjectParameter> output;		///< List of output parameters
  static void readParameter(const Element *el,std::string &name,uint4 &size);
  void orderParameters(void);			///< Assign an index to parameters
public:
  InjectPayload(const std::string &nm,int4 tp) { name=nm; type=tp; paramshift=0; dynamic = false; }	///< Construct for use with restoreXml
  int4 getParamShift(void) const { return paramshift; }	///< Get the number of parameters shifted
  bool isDynamic(void) const { return dynamic; }	///< Return \b true if p-code in the injection is generated dynamically
  int4 sizeInput(void) const { return inputlist.size(); }	///< Return the number of input parameters
  int4 sizeOutput(void) const { return output.size(); }		///< Return the number of output parameters
  InjectParameter &getInput(int4 i) { return inputlist[i]; }	///< Get the i-th input parameter
  InjectParameter &getOutput(int4 i) { return output[i]; }	///< Get the i-th output parameter
  virtual ~InjectPayload(void) {}				///< Destructor

  /// Perform the injection of \b this payload into data-flow.
  ///
  /// P-code operations representing \b this payload are copied into the
  /// controlling analysis context. The provided PcodeEmit object dictates exactly
  /// where the PcodeOp and Varnode objects are inserted and to what container.
  /// An InjectContext object specifies how placeholder elements become concrete Varnodes
  /// in the appropriate context.
  /// \param context is the provided InjectConject object
  /// \param emit is the provovided PcodeEmit object
  virtual void inject(InjectContext &context,PcodeEmit &emit) const=0;

  virtual void restoreXml(const Element *el);		///< Restore \b this payload from an XML stream
  virtual void printTemplate(std::ostream &s) const=0;	///< Print the p-code ops of the injection to a stream (for debugging)
  std::string getName(void) const { return name; }		///< Return the name of the injection
  int4 getType(void) const { return type; }		///< Return the type of injection (CALLFIXUP_TYPE, CALLOTHERFIXUP_TYPE, etc.)
  virtual std::string getSource(void) const=0;		///< Return a std::string describing the \e source of the injection (.cspec, prototype model, etc.)
};

/// \brief A snippet of p-code that can be executed outside of normal analysis
///
/// Essentially a p-code script.  The p-code contained in this snippet needs to be
/// processor agnostic, so any register Varnodes must be temporary (out of the \e unique space)
/// and any control-flow operations must be contained within the snippet (p-code relative addressing).
/// Input and output to the snippet/script is provided by standard injection parameters.
/// The class contains, as a field, a stripped down emulator to run the script and
/// a convenience method evaluate() to feed in concrete values to the input parameters
/// and return a value from a single output parameter.
class ExecutablePcode : public InjectPayload {
  Architecture *glb;			///< The Architecture owning \b this snippet
  std::string source;			///< Description of the source of \b this snippet
  bool built;				///< Whether build() method has run, setting up the emulator
  EmulateSnippet emulator;		///< The emulator
  std::vector<uintb> inputList;		///< Temporary ids of input varnodes
  std::vector<uintb> outputList;		///< Temporary ids of output varnodes
  PcodeEmit *emitter;			///< Emitter (allocated temporarily) for initializing the emulator
  void build(void);			///< Initialize the Emulate object with the snippet p-code
public:
  ExecutablePcode(Architecture *g,const std::string &src,const std::string &nm);	///< Constructor
  virtual ~ExecutablePcode(void) { if (emitter != (PcodeEmit *)0) delete emitter; }
  virtual std::string getSource(void) const { return source; }
  uintb evaluate(const std::vector<uintb> &input);		///< Evaluate the snippet on the given inputs
};

/// \brief A collection of p-code injection payloads
///
/// This is a container of InjectPayload objects that can be applied for a
/// specific Architecture.  Payloads can be read in via XML (restoreXmlInject()) and manually
/// via manualCallFixup() and manualCallOtherFixup().  Each payload is assigned an integer \e id
/// when it is read in, and getPayload() fetches the payload during analysis. The library
/// also associates the formal names of payloads with the id. Payloads of different types,
/// CALLFIXUP_TYPE, CALLOTHERFIXUP_TYPE, etc., are stored in separate namespaces.
///
/// This is an abstract base class. The derived classes determine the type of storage used
/// by the payloads.  The library also provides a reusable InjectContext object to match
/// the payloads, which can be obtained via getCachedContext().
class PcodeInjectLibrary {
protected:
  Architecture *glb;			///< The Architecture to which the injection payloads apply
  uintb tempbase;			///< Offset within \e unique space for allocating temporaries within a payload
  std::vector<InjectPayload *> injection;	///< Registered injections
  std::map<std::string,int4> callFixupMap;	///< std::map of registered call-fixup names to injection id
  std::map<std::string,int4> callOtherFixupMap;	///< std::map of registered callother-fixup names to injection id
  std::map<std::string,int4> callMechFixupMap;	///< std::map of registered mechanism names to injection id
  std::map<std::string,int4> scriptMap;		///< std::map of registered script names to ExecutablePcode id
  std::vector<std::string> callFixupNames;	///< std::map from injectid to call-fixup name
  std::vector<std::string> callOtherTarget;	///< std::map from injectid to callother-fixup target-op name
  std::vector<std::string> callMechTarget;	///< std::map from injectid to call-mech name
  std::vector<std::string> scriptNames;		///< std::map from injectid to script name
  void registerCallFixup(const std::string &fixupName,int4 injectid/* , std::vector<std::string> targets */);
  void registerCallOtherFixup(const std::string &fixupName,int4 injectid);
  void registerCallMechanism(const std::string &fixupName,int4 injectid);
  void registerExeScript(const std::string &scriptName,int4 injectid);

  /// \brief Allocate a new InjectPayload object
  ///
  /// This acts as an InjectPayload factory. The formal name and type of the payload are given,
  /// \b this library allocates a new object that fits with its storage scheme and returns the id.
  /// \param sourceName is a std::string describing the source of the new payload
  /// \param name is the formal name of the payload
  /// \param type is the formal type (CALLFIXUP_TYPE, CALLOTHERFIXUP_TYPE, etc.) of the payload
  /// \return the id associated with the new InjectPayload object
  virtual int4 allocateInject(const std::string &sourceName,const std::string &name,int4 type)=0;

  ///\brief Finalize a payload within the library, once the payload is initialized
  ///
  /// This provides the derived class the opportunity to add the payload name to the
  /// symbol tables or do anything else it needs to once the InjectPayload object
  /// has been fully initialized.
  /// \param injectid is the id of the InjectPayload to finalize
  virtual void registerInject(int4 injectid)=0;
public:
  PcodeInjectLibrary(Architecture *g,uintb tmpbase) { glb = g; tempbase = tmpbase; }	///< Constructor
  virtual ~PcodeInjectLibrary(void);				///< Destructor
  uintb getUniqueBase(void) const { return tempbase; }		///< Get the (current) offset for building temporary registers
  int4 getPayloadId(int4 type,const std::string &nm) const;		///< std::map name and type to the payload id
  InjectPayload *getPayload(int4 id) const { return injection[id]; }	///< Get the InjectPayload by id
  std::string getCallFixupName(int4 injectid) const;			///< Get the call-fixup name associated with an id
  std::string getCallOtherTarget(int4 injectid) const;		///< Get the callother-fixup name associated with an id
  std::string getCallMechanismName(int4 injectid) const;		///< Get the call mechanism name associated with an id
  int4 restoreXmlInject(const std::string &src,const std::string &nm,int4 tp,const Element *el);

  /// \brief A method for reading in p-code generated externally for use in debugging
  ///
  /// Instantiate a special InjectPayloadDynamic object initialized with an
  /// \<injectdebug> tag.  Within the library, this replaces the original InjectPayload,
  /// allowing its p-code to be \e replayed for debugging purposes.
  /// \param el is the \<injectdebug> element
  virtual void restoreDebug(const Element *el) {}

  /// \brief Manually add a call-fixup payload given a compilable snippet of p-code \e source
  ///
  /// The snippet is compiled immediately to produce the payload.
  /// \param name is the formal name of the new payload
  /// \param snippetstring is the compilable snippet of p-code \e source
  /// \return the id of the new payload
  virtual int4 manualCallFixup(const std::string &name,const std::string &snippetstring)=0;

  /// \brief Manually add a callother-fixup payload given a compilable snippet of p-code \e source
  ///
  /// The snippet is compiled immediately to produce the payload. Symbol names for
  /// input and output parameters must be provided to the compiler.
  /// \param name is the formal name of the new payload
  /// \param outname is the name of the output symbol
  /// \param inname is the ordered std::list of input symbol names
  /// \param snippet is the compilable snippet of p-code \e source
  /// \return the id of the new payload
  virtual int4 manualCallOtherFixup(const std::string &name,const std::string &outname,const std::vector<std::string> &inname,
				    const std::string &snippet)=0;

  /// \brief Retrieve a reusable context object for \b this library
  ///
  /// The object returned by this method gets passed to the payload inject() method.
  /// The clear() method must be called between uses.
  /// \return the cached context object
  virtual InjectContext &getCachedContext(void)=0;

  /// \brief Get the array of op-code behaviors for initializing and emulator
  ///
  /// Behaviors are pulled from the underlying architecture in order to initialize
  /// the Emulate object which services the \e p-code \e script payloads.
  /// \return the array of OpBehavior objects indexed by op-code
  virtual const std::vector<OpBehavior *> &getBehaviors(void)=0;
};

} // GhidraDec

#endif
