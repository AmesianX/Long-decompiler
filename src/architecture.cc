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
// Set up decompiler for specific architectures

#include "coreaction.hh"
#ifdef CPUI_RULECOMPILE
#include "rulecompile.hh"
#endif
#ifdef CPUI_STATISTICS
#include <cmath>
#endif

#include <string>
#include <map>
#include <vector>

namespace GhidraDec {

std::vector<ArchitectureCapability *> ArchitectureCapability::thelist;

const uint4 ArchitectureCapability::majorversion = 3;
const uint4 ArchitectureCapability::minorversion = 4;

/// This builds a list of just the ArchitectureCapability extensions
void ArchitectureCapability::initialize(void)

{
  thelist.push_back(this);
}

/// Given a specific file, find an ArchitectureCapability that can handle it.
/// \param filename is the path to the file
/// \return an ArchitectureCapability that can handle it or NULL
ArchitectureCapability *ArchitectureCapability::findCapability(const std::string &filename)

{
  for(uint4 i=0;i<thelist.size();++i) {
    ArchitectureCapability *capa = thelist[i];
    if (capa->isFileMatch(filename))
      return capa;
  }
  return (ArchitectureCapability *)0;
}

/// Given a parsed XML document, find an ArchitectureCapability that can handle it.
/// \param doc is the parsed XML document
/// \return an ArchitectureCapability that can handle it or NULL
ArchitectureCapability *ArchitectureCapability::findCapability(Document *doc)

{
  for(uint4 i=0;i<thelist.size();++i) {
    ArchitectureCapability *capa = thelist[i];
    if (capa->isXmlMatch(doc))
      return capa;
  }
  return (ArchitectureCapability *)0;
}

/// Modify order that extensions are searched, to effect which gets a chance
/// to run first.
/// Right now all we need to do is make sure the raw architecture comes last
void ArchitectureCapability::sortCapabilities(void)

{
  uint4 i;
  for(i=0;i<thelist.size();++i) {
    if (thelist[i]->getName() == "raw") break;
  }
  if (i==thelist.size()) return;
  ArchitectureCapability *capa = thelist[i];
  for(uint4 j=i+1;j<thelist.size();++j)
    thelist[j-1] = thelist[j];
  thelist[ thelist.size()-1 ] = capa;
}

/// Set most sub-components to null pointers. Provide reasonable defaults
/// for the configurable options
Architecture::Architecture(void)

{
  //  endian = -1;
  trim_recurse_max = 5;		// Reasonable default value
  max_implied_ref = 2;		// 2 is best, in specific cases a higher number might be good
  max_term_duplication = 2;	// 2 and 3 (4) are pretty reasonable
  max_basetype_size = 10;	// Needs to be 8 or bigger
  min_funcsymbol_size = 1;
  aggressive_ext_trim = false;
  readonlypropagate = false;
  infer_pointers = true;
  pointer_lowerbound = 0x1000;
  funcptr_align = 0;
  flowoptions = 0;
  defaultfp = (ProtoModel *)0;
  defaultReturnAddr.space = (AddrSpace *)0;
  evalfp_current = (ProtoModel *)0;
  evalfp_called = (ProtoModel *)0;
  types = (TypeFactory *)0;
  translate = (Translate *)0;
  loader = (LoadImage *)0;
  pcodeinjectlib = (PcodeInjectLibrary *)0;
  commentdb = (CommentDatabase *)0;
  cpool = (ConstantPool *)0;
  symboltab = new Database(this);
  context = (ContextDatabase *)0;
  print = PrintLanguageCapability::getDefault()->buildLanguage(this);
  printlist.push_back(print);
  options = new OptionDatabase(this);
  loadersymbols_parsed = false;
#ifdef CPUI_STATISTICS
  stats = new Statistics();
#endif
#ifdef OPACTION_DEBUG
  debugstream = (std::ostream *)0;
#endif
}

/// Release resources for all sub-components
Architecture::~Architecture(void)

{				// Delete anything that was allocated
  std::vector<TypeOp *>::iterator iter;
  TypeOp *t_op;

  for(iter=inst.begin();iter!=inst.end();++iter) {
    t_op = *iter;
    if (t_op != (TypeOp *)0)
      delete t_op;
  }
  for(int4 i=0;i<extra_pool_rules.size();++i)
    delete extra_pool_rules[i];

  delete symboltab;
  for(int4 i=0;i<(int4)printlist.size();++i)
    delete printlist[i];
  delete options;
#ifdef CPUI_STATISTICS
  delete stats;
#endif

  std::map<std::string,ProtoModel *>::const_iterator piter;
  for(piter=protoModels.begin();piter!=protoModels.end();++piter)
    delete (*piter).second;

  if (types != (TypeFactory *)0)
    delete types;
  if (translate != (Translate *)0)
    delete translate;
  if (loader != (LoadImage *)0)
    delete loader;
  if (pcodeinjectlib != (PcodeInjectLibrary *)0)
    delete pcodeinjectlib;
  if (commentdb != (CommentDatabase *)0)
    delete commentdb;
  if (cpool != (ConstantPool *)0)
    delete cpool;
  if (context != (ContextDatabase *)0)
    delete context;
}

/// The Architecture maintains the set of prototype models that can
/// be applied for this particular executable. Retrieve one by name.
/// The model must exist or an exception is thrown.
/// \param nm is the name
/// \return the matching model
ProtoModel *Architecture::getModel(const std::string &nm) const

{
  std::map<std::string,ProtoModel *>::const_iterator iter;

  iter = protoModels.find(nm);
  if (iter==protoModels.end())
    throw LowlevelError("Prototype model does not exist: "+nm);
  return (*iter).second;
}

/// \param nm is the name of the model
/// \return \b true if this Architecture supports a model with that name
bool Architecture::hasModel(const std::string &nm) const

{ // Does this architecture have a prototype model of this name
  std::map<std::string,ProtoModel *>::const_iterator iter;

  iter = protoModels.find(nm);
  return (iter != protoModels.end());
}

/// Get the address space associated with the indicated
/// \e spacebase register. I.e. if the location of the
/// \e stack \e pointer is passed in, this routine would return
/// a pointer to the \b stack space. An exception is thrown
/// if no corresponding space is found.
/// \param loc is the location of the \e spacebase register
/// \param size is the size of the register in bytes
/// \return a pointer to the address space
AddrSpace *Architecture::getSpaceBySpacebase(const Address &loc,int4 size) const

{
  AddrSpace *id;
  int4 sz = numSpaces();
  for(int4 i=0;i<sz;++i) {
    id = getSpace(i);
    int4 numspace = id->numSpacebase();
    for(int4 j=0;j<numspace;++j) {
      const VarnodeData &point(id->getSpacebase(j));
      if (point.size != size) continue;
      if (point.space != loc.getSpace()) continue;
      if (point.offset != loc.getOffset()) continue;
      return id;
    }
  }
  throw LowlevelError("Unable to find entry for spacebase register");
  return (AddrSpace *)0;
}

/// The default model is used whenever an explicit model is not known
/// or can't be determined.
/// \param nm is the name of the model to set
void Architecture::setDefaultModel(const std::string &nm)

{
  defaultfp = getModel(nm);
}

/// Throw out the syntax tree, (unlocked) symbols, comments, and other derived information
/// about a single function.
/// \param fd is the function to clear
void Architecture::clearAnalysis(Funcdata *fd)

{
  fd->clear();			// Clear stuff internal to function
  // Clear out any analysis generated comments
  commentdb->clearType(fd->getAddress(),Comment::warning|Comment::warningheader);
}

/// Symbols do not necessarily need to be available for the decompiler.
/// This routine loads all the \e load \e image knows about into the symbol table
void Architecture::readLoaderSymbols(void)

{
  if (loadersymbols_parsed) return; // already read
  Scope *scope = symboltab->getGlobalScope();
  loader->openSymbols();
  loadersymbols_parsed = true;
  LoadImageFunc record;
  while(loader->getNextSymbol(record)) {
    scope->addFunction(record.address,record.name);
  }
  loader->closeSymbols();
}

/// For all registered p-code opcodes, return the corresponding OpBehavior object.
/// The object pointers are provided in a list indexed by OpCode.
/// \param behave is the list to be populated
void Architecture::collectBehaviors(std::vector<OpBehavior *> &behave) const

{
  behave.resize(inst.size(), (OpBehavior *)0);
  for(int4 i=0;i<inst.size();++i) {
    TypeOp *op = inst[i];
    if (op == (TypeOp *)0) continue;
    behave[i] = op->getBehavior();
  }
}

/// A \b near pointer is some form of truncated pointer that needs
/// \e segment or other information to fully form an address.
/// This method searches for a user-defined segment op registered
/// for the space
/// \param spc is the address space to check
/// \return true if the space supports a segment operation
bool Architecture::hasNearPointers(AddrSpace *spc) const

{
  if (spc->getIndex() >= userops.numSegmentOps()) return false;
  SegmentOp *segdef = userops.getSegmentOp(spc->getIndex());
  if (segdef == (SegmentOp *)0) return false;
  if (segdef->getResolve().space != (AddrSpace *)0)
    return true;
  return false;
}

/// Establish details of the prototype for a given function symbol
/// \param pieces holds the raw prototype information and the symbol name
void Architecture::setPrototype(const PrototypePieces &pieces)

{
  Funcdata *fd = symboltab->getGlobalScope()->queryFunction( pieces.name );
  if (fd == (Funcdata *)0)
    throw ParseError("Unknown function name: "+pieces.name);

  fd->getFuncProto().setPieces(pieces);
}

/// The decompiler supports one or more output languages (C, Java). This method
/// does the main work of selecting one of the supported languages.
/// In addition to selecting the main PrintLanguage object, this triggers
/// configuration of the cast strategy and p-code op behaviors.
/// \param nm is the name of the language
void Architecture::setPrintLanguage(const std::string &nm)

{
  for(int4 i=0;i<(int4)printlist.size();++i) {
    if (printlist[i]->getName() == nm) {
      print = printlist[i];
      print->adjustTypeOperators();
      return;
    }
  }
  PrintLanguageCapability *capa = PrintLanguageCapability::findCapability(nm);
  if (capa == (PrintLanguageCapability *)0)
    throw LowlevelError("Unknown print language: "+nm);
  bool printxml = print->emitsXml(); // Copy settings for current print language
  std::ostream *t = print->getOutputStream();
  print = capa->buildLanguage(this);
  print->setOutputStream(t);	// Restore settings from previous language
  print->getCastStrategy()->setTypeFactory(types);
  if (printxml)
    print->setXML(true);
  printlist.push_back(print);
  print->adjustTypeOperators();
  return;
}

/// Set all IPTR_PROCESSOR and IPTR_SPACEBASE spaces to be global
void Architecture::globalify(void)

{
  Scope *scope = buildGlobalScope();
  int4 nm = numSpaces();

  for(int4 i=0;i<nm;++i) {
    AddrSpace *spc = getSpace(i);
    if ((spc->getType() != IPTR_PROCESSOR)&&(spc->getType() != IPTR_SPACEBASE)) continue;
    symboltab->addRange(scope,spc,(uintb)0,spc->getHighest());
  }
}

/// Insert a series of out-of-band flow overrides based on a \<flowoverridelist> tag.
/// \param el is the XML element
void Architecture::restoreFlowOverride(const Element *el)

{
  const List &list(el->getChildren());
  List::const_iterator iter;

  for(iter=list.begin();iter!=list.end();++iter) {
    const Element *subel = *iter;
    const List &sublist(subel->getChildren());
    List::const_iterator subiter = sublist.begin();
    Address funcaddr = Address::restoreXml(*subiter,this);
    ++subiter;
    Address overaddr = Address::restoreXml(*subiter,this);
    Funcdata *fd = symboltab->getGlobalScope()->queryFunction(funcaddr);
    if (fd != (Funcdata *)0)
      fd->getOverride().insertFlowOverride(overaddr,Override::stringToType(subel->getAttributeValue("type")));
  }
}

/// Write the current state of all types, symbols, functions, etc. an XML stream
/// \param s is the output stream
void Architecture::saveXml(std::ostream &s) const

{
  s << "<save_state";
  a_v_b(s,"loadersymbols",loadersymbols_parsed);
  s << ">\n";
  types->saveXml(s);
  symboltab->saveXml(s);
  context->saveXml(s);
  commentdb->saveXml(s);
  if (!cpool->empty())
    cpool->saveXml(s);
  s << "</save_state>\n";
}

/// Read in all the sub-component state from a \<save_state> XML tag
/// When adding stuff to this BEWARE: The spec file has already initialized stuff
/// \param store is document store containing the parsed root tag
void Architecture::restoreXml(DocumentStorage &store)

{
  const Element *el = store.getTag("save_state");
  if (el == (const Element *)0)
    throw LowlevelError("Could not find save_state tag");
  if (el->getNumAttributes() != 0)
    loadersymbols_parsed = xml_readbool(el->getAttributeValue("loadersymbols"));
  else
    loadersymbols_parsed = false;

  const List &list(el->getChildren());
  List::const_iterator iter;

  for(iter=list.begin();iter!=list.end();++iter) {
    const Element *subel = *iter;
    if (subel->getName() == "typegrp")
      types->restoreXml(subel);
    else if (subel->getName() == "db")
      symboltab->restoreXml(subel);
    else if (subel->getName() == "context_points")
      context->restoreXml(subel,this);
    else if (subel->getName() == "commentdb")
      commentdb->restoreXml(subel,this);
    else if (subel->getName() == "constantpool")
      cpool->restoreXml(subel,*types);
    else if (subel->getName() == "optionslist")
      options->restoreXml(subel);
    else if (subel->getName() == "flowoverridelist")
      restoreFlowOverride(subel);
    else if (subel->getName() == "injectdebug")
      pcodeinjectlib->restoreDebug(subel);
    else
      throw LowlevelError("XML error restoring architecture: " + subel->getName());
  }
}

/// If no better name is available, this method can be used to generate
/// a function name based on its address
/// \param addr is the address of the function
/// \param name will hold the constructed name
void Architecture::nameFunction(const Address &addr,std::string &name) const

{
  ostringstream defname;
  defname << "func_";
  addr.printRaw(defname);
  name = defname.str();
}

/// This process sets up a "register relative" space for this architecture
/// If the name is "stack", this space takes on the role of an "official" stack space
/// Should only be called once during initialization
/// \param basespace is the address space underlying the stack
/// \param nm is the name of the new space
/// \param ptrdata is the register location acting as a pointer into the new space
/// \param truncSize is the (possibly truncated) size of the register that fits the space
/// \param isreversejustified is \b true if small variables are justified opposite of endianness
/// \param stackGrowth is \b true if a stack implemented in this space grows in the negative direction
void Architecture::addSpacebase(AddrSpace *basespace,const std::string &nm,const VarnodeData &ptrdata,
				int4 truncSize,bool isreversejustified,bool stackGrowth)

{
  int4 ind = numSpaces();
  
  SpacebaseSpace *spc = new SpacebaseSpace(this,translate,nm,ind,truncSize,basespace,ptrdata.space->getDelay()+1);
  if (isreversejustified)
    setReverseJustified(spc);
  insertSpace(spc);
  addSpacebasePointer(spc,ptrdata,truncSize,stackGrowth);
}

/// This routine is used by the initialization process to add
/// address ranges to which there is never an (indirect) pointer
/// Should only be called during initialization
/// \param rng is the new range with no aliases to be added
void Architecture::addNoHighPtr(const Range &rng)

{
  nohighptr.insertRange(rng.getSpace(),rng.getFirst(),rng.getLast());
}

/// This builds the \e universal Action for function transformation
/// and instantiates the "decompile" root Action
/// \param store may hold configuration information
void Architecture::buildAction(DocumentStorage &store)

{
  parseExtraRules(store);	// Look for any additional rules
  universal_action(this);
  allacts.setCurrent("decompile");
}

/// This builds the database which holds the status registers setings and other
/// information that can affect disassembly depending on context.
/// \param store may hold configuration information
void Architecture::buildContext(DocumentStorage &store)

{
  context = new ContextInternal();
}

/// If it does not already exist create the glocal Scope object
/// \return the global Scope object
Scope *Architecture::buildGlobalScope(void)

{
  Scope *globscope = symboltab->getGlobalScope();
  if (globscope == (Scope *)0) { // Make sure global scope exists
    globscope = new ScopeInternal("",this);
    symboltab->attachScope(globscope,(Scope *)0);
  }
  return globscope;
}

/// This builds the TypeFactory object specific to this architecture and
/// prepopulates it with the \e core types. Core types may be pulled
/// from the configuration information, or default core types are used.
/// \param store contains possible configuration information
void Architecture::buildTypegrp(DocumentStorage &store)

{
  const Element *el = store.getTag("coretypes");
  types = new TypeFactory(this); // Initialize the object
  if (el != (const Element *)0)
    types->restoreXmlCoreTypes(el);
  else {
    // Put in the core types
    types->setCoreType("void",1,TYPE_VOID,false);
    types->setCoreType("bool",1,TYPE_BOOL,false);
    types->setCoreType("uint1",1,TYPE_UINT,false);
    types->setCoreType("uint2",2,TYPE_UINT,false);
    types->setCoreType("uint4",4,TYPE_UINT,false);
    types->setCoreType("uint8",8,TYPE_UINT,false);
    types->setCoreType("int1",1,TYPE_INT,false);
    types->setCoreType("int2",2,TYPE_INT,false);
    types->setCoreType("int4",4,TYPE_INT,false);
    types->setCoreType("int8",8,TYPE_INT,false);
    types->setCoreType("float4",4,TYPE_FLOAT,false);
    types->setCoreType("float8",8,TYPE_FLOAT,false);
    types->setCoreType("float10",10,TYPE_FLOAT,false);
    types->setCoreType("float16",16,TYPE_FLOAT,false);
    types->setCoreType("xunknown1",1,TYPE_UNKNOWN,false);
    types->setCoreType("xunknown2",2,TYPE_UNKNOWN,false);
    types->setCoreType("xunknown4",4,TYPE_UNKNOWN,false);
    types->setCoreType("xunknown8",8,TYPE_UNKNOWN,false);
    types->setCoreType("code",1,TYPE_CODE,false);
    types->setCoreType("char",1,TYPE_INT,true);
    types->setCoreType("wchar2",2,TYPE_INT,true);
    types->setCoreType("wchar4",4,TYPE_INT,true);
    types->cacheCoreTypes();
  }
}

/// Build the container that holds comments for executable in this Architecture.
/// \param store may hold configuration information
void Architecture::buildCommentDB(DocumentStorage &store)

{
  commentdb = new CommentDatabaseInternal();
}

/// Some processor models (Java byte-code) need a database of constants.
/// The database is always built, but may remain empty.
/// \param store may hold configuration information
void Architecture::buildConstantPool(DocumentStorage &store)

{
  cpool = new ConstantPoolInternal();
}

/// This registers the OpBehavior objects for all known p-code OpCodes.
/// The Translate and TypeFactory object should already be built.
/// \param store may hold configuration information
void Architecture::buildInstructions(DocumentStorage &store)

{
  TypeOp::registerInstructions(inst,types,translate);
}

/// Once the processor is known, the Translate object can be built and
/// fully initialized. Processor and compiler specific configuration is performed
/// \param store will hold parsed configuration information
void Architecture::restoreFromSpec(DocumentStorage &store)

{
  Translate *newtrans = buildTranslator(store); // Once language is described we can build translator
  newtrans->initialize(store);
  translate = newtrans;
  modifySpaces(newtrans);	// Give architecture chance to modify spaces, before copying
  copySpaces(newtrans);
  insertSpace( new FspecSpace(this,translate,"fspec",numSpaces()));
  insertSpace( new IopSpace(this,translate,"iop",numSpaces()));
  insertSpace( new JoinSpace(this,translate,"join",numSpaces()));
  if (translate->getDefaultSize() < 3) // For small architectures
    pointer_lowerbound = 0x100;	// assume constants are pointers starting at a much lower bound
  userops.initialize(this);
  if (translate->getAlignment() <= 8)
    min_funcsymbol_size = translate->getAlignment();
  pcodeinjectlib = buildPcodeInjectLibrary();
  parseProcessorConfig(store);
  newtrans->setDefaultFloatFormats(); // If no explicit formats registered, put in defaults
  parseCompilerConfig(store);
  // Action stuff will go here
  buildAction(store);
}

/// If any address space supports near pointers and segment operators,
/// setup SegmentedResolver objects that can be used to recover full pointers in context.
void Architecture::initializeSegments(void)

{
  int4 sz = userops.numSegmentOps();
  for(int4 i=0;i<sz;++i) {
    SegmentOp *sop = userops.getSegmentOp(i);
    if (sop == (SegmentOp *)0) continue;
    SegmentedResolver *rsolv = new SegmentedResolver(this,sop->getSpace(),sop);
    insertResolver(sop->getSpace(),rsolv);
  }
}

/// Recover information out of a \<rule> tag and build the new Rule object.
/// \param el is the XML element
void Architecture::parseDynamicRule(const Element *el)

{
  std::string rulename,groupname,enabled;
  for(int4 i=0;i<el->getNumAttributes();++i) {
    if (el->getAttributeName(i) == "name")
      rulename = el->getAttributeValue(i);
    else if (el->getAttributeName(i) == "group")
      groupname = el->getAttributeValue(i);
    else if (el->getAttributeName(i) == "enable")
      enabled = el->getAttributeValue(i);
    else
      throw LowlevelError("Dynamic rule tag contains unknown attribute: "+el->getAttributeName(i));
  }
  if (rulename.size()==0)
    throw LowlevelError("Dynamic rule has no name");
  if (groupname.size()==0)
    throw LowlevelError("Dynamic rule has no group");
  if (enabled == "false") return;
#ifdef CPUI_RULECOMPILE
  Rule *dynrule = RuleGeneric::build(rulename,groupname,el->getContent());
  extra_pool_rules.push_back(dynrule);
#else
  throw LowlevelError("Dynamic rules have not been enabled for this decompiler");
#endif
}

/// This handles the \<prototype> and \<resolveprototype> tags. It builds the
/// ProtoModel object based on the tag and makes it available generally to the decompiler.
/// \param el is the XML tag element
ProtoModel *Architecture::parseProto(const Element *el)

{
  ProtoModel *res;
  if (el->getName() == "prototype")
    res = new ProtoModel(this);
  else if (el->getName() == "resolveprototype")
    res = new ProtoModelMerged(this);
  else
    throw LowlevelError("Expecting <prototype> or <resolveprototype> tag");

  res->restoreXml(el);
  
  ProtoModel *other = protoModels[res->getName()];
  if (other != (ProtoModel *)0) {
    delete res;
    throw LowlevelError("Duplicate ProtoModel name: "+res->getName());
  }
  protoModels[res->getName()] = res;
  return res;
}

/// This supports the \<eval_called_prototype> and \<eval_current_prototype> tag.
/// This determines which prototype model to assume when recovering the prototype
/// for a \e called function and the \e current function respectively.
/// \param el is the XML element
void Architecture::parseProtoEval(const Element *el)

{
  ProtoModel *res = protoModels[ el->getAttributeValue("name") ];
  if (res == (ProtoModel *)0)
    throw LowlevelError("Unknown prototype model name: "+el->getAttributeValue("name"));

  if (el->getName() == "eval_called_prototype") {
    if (evalfp_called != (ProtoModel *)0)
      throw LowlevelError("Duplicate <eval_called_prototype> tag");
    evalfp_called = res;
  }
  else {
    if (evalfp_current != (ProtoModel *)0)
      throw LowlevelError("Duplicate <eval_current_prototype> tag");
    evalfp_current = res;
  }
}

/// There should be exactly one \<default_proto> tag that specifies what the
/// default prototype model is. This builds the ProtoModel object and sets it
/// as the default.
/// \param el is the XML element
void Architecture::parseDefaultProto(const Element *el)

{
  const List &list(el->getChildren());
  List::const_iterator iter;

  for(iter=list.begin();iter!=list.end();++iter) {
    if (defaultfp != (ProtoModel *)0)
      throw LowlevelError("More than one default prototype model");
    defaultfp = parseProto(*iter);
  }
}

/// This handles the \<global> tag adding an address space (or part of the space)
/// to the global scope. Varnodes in this region will be assumed to be global variables.
/// \param el is the XML element
void Architecture::parseGlobal(const Element *el)

{
  Scope *scope = buildGlobalScope();
  const List &list(el->getChildren());
  List::const_iterator iter;
  
  for(iter=list.begin();iter!=list.end();++iter) {
    Range range;
    range.restoreXml(*iter,this);
    symboltab->addRange(scope,range.getSpace(),range.getFirst(),range.getLast());
    if (range.getSpace()->isOverlayBase()) { // If the address space is overlayed
      // We need to duplicate the range being marked as global into the overlay space(s)
      int4 num = numSpaces();
      for(int4 i=0;i<num;++i) {
	OverlaySpace *ospc = (OverlaySpace *)getSpace(i);
	if (!ospc->isOverlay()) continue;
	if (ospc->getBaseSpace() != range.getSpace()) continue;
	symboltab->addRange(scope,ospc,range.getFirst(),range.getLast());
      }
    }
  }
}

/// This applies info from a \<readonly> tag marking a specific region
/// of the executable as \e read-only.
/// \param el is the XML element
void Architecture::parseReadOnly(const Element *el)

{
  const List &list(el->getChildren());
  List::const_iterator iter;
  
  for(iter=list.begin();iter!=list.end();++iter) {
    Range range;
    range.restoreXml(*iter,this);
    symboltab->setPropertyRange(Varnode::readonly,range);
  }
}

/// This applies info from a \<volatile> tag marking specific regions
/// of the executable as holding \e volatile memory or registers.
/// \param el is the XML element
void Architecture::parseVolatile(const Element *el)

{
  userops.parseVolatile(el,this);
  const List &list(el->getChildren());
  List::const_iterator iter;
  
  for(iter=list.begin();iter!=list.end();++iter) {
    Range range;
    range.restoreXml(*iter,this); // Tag itself is range
    symboltab->setPropertyRange(Varnode::volatil,range);
  }
}

/// This applies info from \<returnaddress> tag and sets the default
/// storage location for the \e return \e address of a function.
/// \param el is the XML element
void Architecture::parseReturnAddress(const Element *el)

{
  const List &list(el->getChildren());
  List::const_iterator iter;

  iter = list.begin();
  if (iter == list.end()) return;
  if (defaultReturnAddr.space != (AddrSpace *)0)
    throw LowlevelError("Multiple <returnaddress> tags in .cspec");
  defaultReturnAddr.restoreXml(*iter,this);
}

/// Apply information from an \<incidentalcopy> tag, which marks a set of addresses
/// as being copied to incidentally. This allows the decompiler to ignore certain side-effects.
/// \param el is the XML element
void Architecture::parseIncidentalCopy(const Element *el)

{
  const List &list(el->getChildren());
  List::const_iterator iter;

  for(iter=list.begin();iter!=list.end();++iter) {
    VarnodeData vdata;
    vdata.restoreXml(*iter,this);
    Range range( vdata.space, vdata.offset, vdata.offset+vdata.size-1);
    symboltab->setPropertyRange(Varnode::incidental_copy,range);
  }
}

/// Create a stack space and a stack-pointer register from this \<stackpointer> element
/// \param el is the XML element
void Architecture::parseStackPointer(const Element *el)

{
  AddrSpace *basespace = getSpaceByName(el->getAttributeValue("space"));
  bool stackGrowth = true;		// Default stack growth is in negative direction
  if (basespace == (AddrSpace *)0)
    throw LowlevelError("Unknown space name: "+el->getAttributeValue("space"));

  bool isreversejustify = false;
  int4 numattr = el->getNumAttributes();
  for(int4 i=0;i<numattr;++i) {
    const std::string &attr( el->getAttributeName(i) );
    if (attr == "reversejustify")
      isreversejustify = xml_readbool(el->getAttributeValue(i));
    else if (attr == "growth")
      stackGrowth = el->getAttributeValue(i) == "negative";
  }

  VarnodeData point = translate->getRegister(el->getAttributeValue("register"));
  // If creating a stackpointer to a truncated space, make sure to truncate the stackpointer
  int4 truncSize = point.size;
  if (basespace->isTruncated() && (point.size > basespace->getAddrSize())) {
    truncSize = basespace->getAddrSize();
  }

  addSpacebase(basespace,"stack",point,truncSize,isreversejustify,stackGrowth); // Create the "official" stackpointer
}

/// Manually alter the dead-code delay for a specific address space,
/// based on a \<deadcodedelay> tag.
/// \param el is the XML element
void Architecture::parseDeadcodeDelay(const Element *el)

{
  AddrSpace *spc = getSpaceByName(el->getAttributeValue("space"));
  if (spc == (AddrSpace *)0)
    throw LowlevelError("Unknown space name: "+el->getAttributeValue("space"));
  istringstream s(el->getAttributeValue("delay"));
  s.unsetf(std::ios::dec | std::ios::hex | std::ios::oct);
  int4 delay = -1;
  s >> delay;
  if (delay >= 0)
    setDeadcodeDelay(spc->getIndex(),delay);
  else
    throw LowlevelError("Bad <deadcodedelay> tag");
}

/// Pull information from a \<funcptr> tag. Turn on alignment analysis of
/// function pointers, some architectures have aligned function pointers
/// and encode extra information in the unused bits.
/// \param el is the XML element
void Architecture::parseFuncPtrAlign(const Element *el)

{
  int4 align;
  istringstream s(el->getAttributeValue("align"));
  s.unsetf(std::ios::dec | std::ios::hex | std::ios::oct);
  s >> align;
  
  if (align == 0) {
    funcptr_align = 0;		// No alignment
    return;
  }
  int4 bits = 0;
  while((align&1)==0) {		// Find position of first 1 bit
    bits += 1;
    align >>= 1;
  }
  funcptr_align = bits;
}

/// Designate a new index register and create a new address space associated with it,
/// based on a \<spacebase> tag.
/// \param el is the XML element
void Architecture::parseSpacebase(const Element *el)

{
  const std::string &namestring(el->getAttributeValue("name"));
  const VarnodeData &point(translate->getRegister(el->getAttributeValue("register")));
  AddrSpace *basespace = getSpaceByName(el->getAttributeValue("space"));
  if (basespace == (AddrSpace *)0)
    throw LowlevelError("Unknown space name: "+el->getAttributeValue("space"));
  addSpacebase(basespace,namestring,point,point.size,false,false);
}

/// Configure memory based on a \<nohighptr> tag. Mark specific address ranges
/// to indicate the decompiler will not encounter pointers (aliases) into the range.
/// \param el is the XML element
void Architecture::parseNoHighPtr(const Element *el)

{
  const List &list(el->getChildren());
  List::const_iterator iter;
  
  for(iter=list.begin();iter!=list.end();++iter) { // Iterate over every range tag in the list
    Range range;
    range.restoreXml(*iter,this);
    addNoHighPtr(range);
  }
}

/// Configure registers based on a \<prefersplit> tag. Mark specific varnodes that
/// the decompiler should automatically split when it first sees them.
/// \param el is the XML element
void Architecture::parsePreferSplit(const Element *el)

{
  std::string style = el->getAttributeValue("style");
  if (style != "inhalf")
    throw LowlevelError("Unknown prefersplit style: "+style);
  const List &list(el->getChildren());
  List::const_iterator iter;

  for(iter=list.begin();iter!=list.end();++iter) {
    splitrecords.push_back(PreferSplitRecord());
    PreferSplitRecord &record( splitrecords.back() );
    record.storage.restoreXml( *iter, this );
    record.splitoffset = record.storage.size/2;
  }
}

/// Configure based on the \<aggressivetrim> tag, how aggressively the
/// decompiler will remove extension operations.
/// \param el is the XML element
void Architecture::parseAggressiveTrim(const Element *el)

{
  int4 sz = el->getNumAttributes();
  for(int4 i=0;i<sz;++i) {
    const std::string &nm( el->getAttributeName(i) );
    if (nm == "signext") {
      aggressive_ext_trim = xml_readbool(el->getAttributeValue(i));
    }
  }
}

/// This looks for the \<processor_spec> tag and and sets configuration
/// parameters based on it.
/// \param store is the document store holding the tag
void Architecture::parseProcessorConfig(DocumentStorage &store)

{
  const Element *el = store.getTag("processor_spec");
  if (el == (const Element *)0)
    throw LowlevelError("No processor configuration tag found");
  const List &list(el->getChildren());
  List::const_iterator iter;
  
  for(iter=list.begin();iter!=list.end();++iter) {
    if ((*iter)->getName() == "programcounter") {
    }
    else if ((*iter)->getName() == "volatile")
      parseVolatile(*iter);
    else if ((*iter)->getName() == "incidentalcopy")
      parseIncidentalCopy(*iter);
    else if ((*iter)->getName() == "context_data")
      context->restoreFromSpec(*iter,this);
    else if ((*iter)->getName() == "jumpassist")
      userops.parseJumpAssist(*iter, this);
    else if ((*iter)->getName() == "register_data") {
    }
    else if ((*iter)->getName() == "segmented_address") {
    }
    else if ((*iter)->getName() == "default_symbols") {
    }
    else if ((*iter)->getName() == "default_memory_blocks") {
    }
    else if ((*iter)->getName() == "address_shift_amount") {
    }
    else if ((*iter)->getName() == "properties") {
    }
    else if ((*iter)->getName() == "data_space") {
    }
    else
      throw LowlevelError("Unknown element in <processor_spec>: "+(*iter)->getName());
  }
}

/// This looks for the \<compiler_spec> tag and sets configuration parameters based on it.
/// \param store is the document store holding the tag
void Architecture::parseCompilerConfig(DocumentStorage &store)

{
  std::vector<const Element *> globaltags;
  const Element *el = store.getTag("compiler_spec");
  if (el == (const Element *)0)
    throw LowlevelError("No compiler configuration tag found");
  const List &list(el->getChildren());
  List::const_iterator iter;

  for(iter=list.begin();iter!=list.end();++iter) {
    const std::string &elname( (*iter)->getName() );
    if (elname == "default_proto")
      parseDefaultProto(*iter);
    else if (elname == "prototype")
      parseProto(*iter);
    else if (elname == "stackpointer")
      parseStackPointer(*iter);
    else if (elname == "returnaddress")
      parseReturnAddress(*iter);
    else if (elname == "spacebase")
      parseSpacebase(*iter);
    else if (elname == "nohighptr")
      parseNoHighPtr(*iter);
    else if (elname == "prefersplit")
      parsePreferSplit(*iter);
    else if (elname == "aggressivetrim")
      parseAggressiveTrim(*iter);
    else if (elname == "data_organization")
      types->parseDataOrganization(*iter);
    else if (elname == "enum")
      types->parseEnumConfig(*iter);
    else if (elname == "global")
      globaltags.push_back(*iter);
    else if (elname == "segmentop")
      userops.parseSegmentOp(*iter,this);
    else if (elname == "readonly")
      parseReadOnly(*iter);
    else if (elname == "context_data")
      context->restoreFromSpec(*iter,this);
    else if (elname == "resolveprototype")
      parseProto(*iter);
    else if (elname == "eval_called_prototype")
      parseProtoEval(*iter);
    else if (elname == "eval_current_prototype")
      parseProtoEval(*iter);
    else if (elname == "callfixup") {
      pcodeinjectlib->restoreXmlInject(archid+" : compiler spec", (*iter)->getAttributeValue("name"),
				       InjectPayload::CALLFIXUP_TYPE, *iter);
    }
    else if (elname == "callotherfixup") {
      userops.parseCallOtherFixup(*iter,this);
    }
    else if (elname == "funcptr")
      parseFuncPtrAlign(*iter);
    else if (elname == "deadcodedelay")
      parseDeadcodeDelay(*iter);
  }
                                        // <global> tags instantiate the base symbol table
                                        // They need to know about all spaces, so it must come
                                        // after parsing of <stackpointer> and <spacebase>
  for(int4 i=0;i<globaltags.size();++i)
    parseGlobal(globaltags[i]);
      
  if (defaultfp == (ProtoModel *)0) {
    if (protoModels.size() == 1)
      defaultfp = (*protoModels.begin()).second;
    else
      throw LowlevelError("No default prototype specified");
  }
  // We must have a __thiscall calling convention
  std::map<std::string,ProtoModel *>::iterator miter = protoModels.find("__thiscall");
  if (miter == protoModels.end()) { // If __thiscall doesn't exist we clone it off of the default
    ProtoModel *thismodel = new ProtoModel("__thiscall",*defaultfp);
    protoModels["__thiscall"] = thismodel;
  }
  userops.setDefaults(this);
  initializeSegments();
  PreferSplitManager::initialize(splitrecords);
  types->setupSizes();		// If no data_organization was registered, set up default values
}

/// Look for the \<experimental_rules> tag and create any dynamic Rule objects it specifies.
/// \param store is the document store containing the tag
void Architecture::parseExtraRules(DocumentStorage &store)

{
  const Element *expertag = store.getTag("experimental_rules");
  if (expertag != (const Element *)0) {
    const List &list(expertag->getChildren());
    List::const_iterator iter;
    
    for(iter=list.begin();iter!=list.end();++iter)
      parseDynamicRule( *iter );
  }
}

/// The LoadImage may have access information about the executables
/// sections. Query for any read-only ranges and
/// store this information in the property database
void Architecture::fillinReadOnlyFromLoader(void)

{
  RangeList rangelist;
  loader->getReadonly(rangelist); // Get read only ranges
  set<Range>::const_iterator iter,eiter;
  iter = rangelist.begin();
  eiter = rangelist.end();
  while(iter != eiter) {
    symboltab->setPropertyRange(Varnode::readonly,*iter);
    ++iter;
  }
}

/// Create the LoadImage and load the executable to be analyzed.
/// Using this and possibly other initialization information, create
/// all the sub-components necessary for a complete Architecture
/// The DocumentStore may hold previously gleaned configuration information
/// and is used to read in other configuration files while initializing.
/// \param store is the XML document store
void Architecture::init(DocumentStorage &store)

{
  buildLoader(store);		// Loader is built first
  resolveArchitecture();
  buildSpecFile(store);

  buildContext(store);
  buildTypegrp(store);
  buildCommentDB(store);
  buildConstantPool(store);

  restoreFromSpec(store);
  print->getCastStrategy()->setTypeFactory(types);
  postSpecFile();		// Let subclasses do things after translate is ready

  buildInstructions(store); // Must be called after translate is built
  fillinReadOnlyFromLoader();
}

Address SegmentedResolver::resolve(uintb val,int4 sz,const Address &point)

{
  int4 innersz = segop->getInnerSize();
  if (sz <= innersz) { // If -sz- matches the inner size, consider the value a "near" pointer
  // In this case the address offset is not fully specified
  // we check if the rest is stored in a context variable
  // (as with near pointers)
    if (segop->getResolve().space != (AddrSpace *)0) {
      uintb base = glb->context->getTrackedValue(segop->getResolve(),point);
      std::vector<uintb> seginput;
      seginput.push_back(val);
      seginput.push_back(base);
      val = segop->execute(seginput);
      return Address(spc,AddrSpace::addressToByte(val,spc->getWordSize()));
    }
  }
  else { // For anything else, consider it a "far" pointer
    int4 outersz = segop->getBaseSize();
    uintb base = (val >> 8*innersz) & calc_mask(outersz);
    val = val & calc_mask(innersz);
    std::vector<uintb> seginput;
    seginput.push_back(val);
    seginput.push_back(base);
    val = segop->execute(seginput);
    return Address(spc,AddrSpace::addressToByte(val,spc->getWordSize()));
  }
  return Address();		// Return invalid address
}

#ifdef CPUI_STATISTICS

Statistics::Statistics(void)

{
  numfunc = 0;
//   numvar = 0;
//   coversum = 0;
//   coversumsq = 0;
  castcount = 0;
  lastcastcount = 0;
  castcountsq = 0;
}

Statistics::~Statistics(void)

{
}

// void Statistics::process_cover(const Funcdata &data)

// {
//   if (data.getBasicBlocks().getSize() < 100) return;
//   VarnodeLocSet::const_iterator iter;
//   for(iter=data.beginLoc();iter!=data.endLoc();++iter) {
//     Varnode *vn = *iter;

//     if (!vn->hasCover()) continue;
//     Cover *cover = vn->getCover();
//     if (cover == (Cover *)0) continue;
//     numvar += 1;
    
//     int4 size = cover->getSize();
//     int4 count = 0;
//     for(int4 i=0;i<size;++i) {
//       if (!cover->getCoverBlock(i).empty())
// 	count += 1;
//     }
//     coversum += count;		// Number of non-empty covers
//     coversumsq += ((uintb)count)*((uintb)count);
//   }
// }

/// Calculate number of casts seen since last function, update variance
/// \param data is the function being analyzed
void Statistics::process_cast(const Funcdata &data)

{
  uintb perfunc = castcount - lastcastcount;
  lastcastcount = castcount;
  castcountsq += perfunc*perfunc;
}

/// Gather various statistics for a single function and accumulate in global counts
/// \param data is the function being analyzed
void Statistics::process(const Funcdata &data)

{
  numfunc += 1;
  //  process_cover(data);
  process_cast(data);
}

/// Complete calculations on running sums then print them to a stream
/// \param s is the output stream
void Statistics::printResults(std::ostream &s)

{
  s << "Number of functions: " << dec << numfunc << endl;
  //  s << "Number of variables: " << dec << numvar << endl;

  //  double average = ((double)coversum)/numvar;
  //  double variance = ((double)coversumsq)/numvar;
  //  double stddev = sqrt(variance);

  //  s << "Average number of non-empty covers: " << average << endl;
  //  s << "Standard deviation: " << stddev << endl;

  double average = ((double)castcount)/numfunc;
  double variance = ((double)castcountsq)/numfunc;
  variance -= average*average;
  double stddev = sqrt(variance);

  s << "Total functions = " << dec << numfunc << endl;
  s << "Total casts = " << dec << castcount << endl;
  s << "Average casts per function = " << average << endl;
  s << "        Standard deviation = " << stddev << endl;
}

#endif
}
