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
#include "translate.hh"

namespace GhidraDec {
/// Read a \<truncate_space> XML tag to configure \b this object
/// \param el is the XML element
void TruncationTag::restoreXml(const Element *el)

{
  spaceName = el->getAttributeValue("space");
  std::istringstream s(el->getAttributeValue("size"));
  s.unsetf(std::ios::dec | std::ios::hex | std::ios::oct);
  s >> size;
}

/// Construct a virtual space.  This is usually used for the stack
/// space, but multiple such spaces are allowed.
/// \param m is the manager for this \b program \b specific address space
/// \param t is associated processor translator
/// \param nm is the name of the space
/// \param ind is the integer identifier
/// \param sz is the size of the space
/// \param base is the containing space
/// \param dl is the heritage delay
SpacebaseSpace::SpacebaseSpace(AddrSpaceManager *m,const Translate *t,const string &nm,int4 ind,int4 sz,
			       AddrSpace *base,int4 dl)
  : AddrSpace(m,t,IPTR_SPACEBASE,nm,sz,base->getWordSize(),ind,0,dl)
{
  contain = base;
  hasbaseregister = false;	// No base register assigned yet
  isNegativeStack = true;	// default stack growth
}

/// This is a partial constructor, which must be followed up
/// with restoreXml in order to fillin the rest of the spaces
/// attributes
/// \param m is the associated address space manager
/// \param t is the associated processor translator
SpacebaseSpace::SpacebaseSpace(AddrSpaceManager *m,const Translate *t)
  : AddrSpace(m,t,IPTR_SPACEBASE)
{
  hasbaseregister = false;
  isNegativeStack = true;
  setFlags(programspecific);
}

/// This routine sets the base register associated with this \b virtual space
/// It will throw an exception if something tries to std::set two (different) base registers
/// \param data is the location data for the base register
/// \param truncSize is the size of the space covered by the register
/// \param stackGrowth is \b true if the stack which this register manages grows in a negative direction
void SpacebaseSpace::setBaseRegister(const VarnodeData &data,int4 truncSize,bool stackGrowth)

{
  if (hasbaseregister) {
    if ((baseloc != data)||(isNegativeStack != stackGrowth))
      throw LowlevelError("Attempt to assign more than one base register to space: "+getName());
  }
  hasbaseregister = true;
  isNegativeStack = stackGrowth;
  baseOrig = data;
  baseloc = data;
  if (truncSize != baseloc.size) {
    if (baseloc.space->isBigEndian())
      baseloc.offset += (baseloc.size - truncSize);
    baseloc.size = truncSize;
  }
}

int4 SpacebaseSpace::numSpacebase(void) const

{
  return hasbaseregister ? 1 : 0;
}

const VarnodeData &SpacebaseSpace::getSpacebase(int4 i) const

{
  if ((!hasbaseregister)||(i!=0))
    throw LowlevelError("No base register specified for space: "+getName());
  return baseloc;
}

const VarnodeData &SpacebaseSpace::getSpacebaseFull(int4 i) const

{
  if ((!hasbaseregister)||(i!=0))
    throw LowlevelError("No base register specified for space: "+getName());
  return baseOrig;
}

void SpacebaseSpace::saveXml(ostream &s) const

{
  s << "<space_base";
  saveBasicAttributes(s);
  a_v(s,"contain",contain->getName());
  s << "/>\n";
}

void SpacebaseSpace::restoreXml(const Element *el)

{
  AddrSpace::restoreXml(el);	// Restore basic attributes
  contain = getManager()->getSpaceByName(el->getAttributeValue("contain"));
}

/// Allow sorting on JoinRecords so that a collection of pieces can be quickly mapped to
/// its logical whole, specified with a join address
bool JoinRecord::operator<(const JoinRecord &op2) const

{
  // Some joins may have same piece but different unified size  (floating point)
  if (unified.size != op2.unified.size) // Compare size first
    return (unified.size < op2.unified.size);
  // Lexigraphic sort on pieces
  int4 i=0;
  for(;;) {
    if (pieces.size()==i) {
      return (op2.pieces.size()>i); // If more pieces in op2, it is bigger (return true), if same number this==op2, return false
    }
    if (op2.pieces.size()==i) return false; // More pieces in -this-, so it is bigger, return false
    if (pieces[i] != op2.pieces[i])
      return (pieces[i] < op2.pieces[i]);
    i += 1;
  }
}

/// Initialize manager containing no address spaces. All the cached space slots are std::set to null
AddrSpaceManager::AddrSpaceManager(void)

{
  defaultspace = (AddrSpace *)0;
  constantspace = (AddrSpace *)0;
  iopspace = (AddrSpace *)0;
  fspecspace = (AddrSpace *)0;
  joinspace = (AddrSpace *)0;
  stackspace = (AddrSpace *)0;
  uniqspace = (AddrSpace *)0;
  joinallocate = 0;
}

/// The initialization of address spaces is the same across all
/// variants of the Translate object.  This routine initializes
/// a single address space from a parsed XML tag.  It knows
/// which class derived from AddrSpace to instantiate based on
/// the tag name.
/// \param el is the parsed XML tag
/// \param trans is the translator object to be associated with the new space
/// \return a pointer to the initialized AddrSpace
AddrSpace *AddrSpaceManager::restoreXmlSpace(const Element *el,const Translate *trans)

{
  AddrSpace *res;
  const string &tp(el->getName());
  if (tp == "space_base")
    res = new SpacebaseSpace(this,trans);
  else if (tp == "space_unique")
    res = new UniqueSpace(this,trans);
  else if (tp == "space_overlay")
    res = new OverlaySpace(this,trans);
  else
    res = new AddrSpace(this,trans,IPTR_PROCESSOR);

  res->restoreXml(el);
  return res;
}

/// This routine initializes (almost) all the address spaces used
/// for a particular processor by using a \b \<spaces\> tag,
/// which contains subtags for the specific address spaces.
/// This also instantiates the builtin \e constant space. It
/// should probably also instantiate the \b iop, \b fspec, and \b join
/// spaces, but this is currently done by the Architecture class.
/// \param el is the parsed \b \<spaces\> tag
/// \param trans is the processor translator to be associated with the spaces
void AddrSpaceManager::restoreXmlSpaces(const Element *el,const Translate *trans)

{
  // The first space should always be the constant space
  insertSpace(new ConstantSpace(this,trans,"const",0));

  string defname(el->getAttributeValue("defaultspace"));
  const List &list(el->getChildren());
  List::const_iterator iter;
  iter = list.begin();
  while(iter!=list.end()) {
    AddrSpace *spc = restoreXmlSpace(*iter,trans);
    insertSpace(spc);
    ++iter;
  }
  AddrSpace *spc = getSpaceByName(defname);
  setDefaultSpace(spc->getIndex());
}

/// Once all the address spaces have been initialized, this routine
/// should be called once to establish the official \e default
/// space for the processor, via its index. Should only be
/// called during initialization.
/// \todo This really shouldn't be public
/// \param index is the index of the desired default space
void AddrSpaceManager::setDefaultSpace(int4 index)

{
  if (defaultspace != (AddrSpace *)0)
    throw LowlevelError("Default space std::set multiple times");
  if (baselist.size()<=index)
    throw LowlevelError("Bad index for default space");
  defaultspace = baselist[index];
}

/// For spaces with alignment restrictions, the address of a small variable must be justified
/// within a larger aligned memory word, usually either to the left boundary for little endian encoding
/// or to the right boundary for big endian encoding.  Some compilers justify small variables to
/// the opposite side of the one indicated by the endianness. Setting this property on a space
/// causes the decompiler to use this justification
void AddrSpaceManager::setReverseJustified(AddrSpace *spc)

{
  spc->setFlags(AddrSpace::reverse_justification);
}

/// This adds a previously instantiated address space (AddrSpace)
/// to the model for this processor.  It checks a std::set of
/// indexing and naming conventions for the space and throws
/// an exception if the conventions are violated. Should
/// only be called during initialization.
/// \todo This really shouldn't be public.  Need to move the
/// allocation of \b iop, \b fspec, and \b join out of Architecture
/// \param spc the address space to insert
void AddrSpaceManager::insertSpace(AddrSpace *spc)

{
  bool nametype_mismatch = false;
  bool duplicatedefine = false;
  switch(spc->getType()) {
  case IPTR_CONSTANT:
    if (spc->getName() != "const")
      nametype_mismatch = true;
    if (baselist.size()!=0)
      throw LowlevelError("const space must be initialized first");
    constantspace = spc;
    break;
  case IPTR_INTERNAL:
    if (spc->getName() != "unique")
      nametype_mismatch = true;
    if (uniqspace != (AddrSpace *)0)
      duplicatedefine = true;
    uniqspace = spc;
    break;
  case IPTR_FSPEC:
    if (spc->getName() != "fspec")
      nametype_mismatch = true;
    if (fspecspace != (AddrSpace *)0)
      duplicatedefine = true;
    fspecspace = spc;
    break;
  case IPTR_JOIN:
    if (spc->getName() != "join")
      nametype_mismatch = true;
    if (joinspace != (AddrSpace *)0)
      duplicatedefine = true;
    joinspace = spc;
    break;
  case IPTR_IOP:
    if (spc->getName() != "iop")
      nametype_mismatch = true;
    if (iopspace != (AddrSpace *)0)
      duplicatedefine = true;
    iopspace = spc;
    break;
  case IPTR_SPACEBASE:
    if (spc->getName() == "stack") {
      if (stackspace != (AddrSpace *)0)
	duplicatedefine = true;
      stackspace = spc;
    }
    // fallthru
  case IPTR_PROCESSOR:
    if (spc->isOverlay()) {	// If this is a new overlay space
      OverlaySpace *ospc = (OverlaySpace *)spc;
      ospc->getBaseSpace()->setFlags(AddrSpace::overlaybase); // Mark the base as being overlayed
    }
    for(uint4 i=0;i<baselist.size();++i)
      if (baselist[i]->getName() == spc->getName())
	duplicatedefine = true;
    break;
  }
  if (nametype_mismatch)
    throw LowlevelError("Space "+spc->getName()+" was initialized with wrong type");
  if (duplicatedefine)
    throw LowlevelError("Space "+spc->getName()+" was initialized more than once");
  if (baselist.size() != spc->getIndex())
    throw LowlevelError("Space "+spc->getName()+" was initialized with a bad id");
  baselist.push_back(spc);
  spc->refcount += 1;
}

/// Different managers may need to share the same spaces. I.e. if different programs being
/// analyzed share the same processor. This routine pulls in a reference of every space in -op2-
/// in order to manage it from within -this-
/// \param op2 is a pointer to space manager being copied
void AddrSpaceManager::copySpaces(const AddrSpaceManager *op2)

{ // Insert every space in -op2- into -this- manager
  for(int4 i=0;i<op2->baselist.size();++i)
    insertSpace(op2->baselist[i]);
  setDefaultSpace(op2->getDefaultSpace()->getIndex());
}

/// Perform the \e privileged act of associating a base register with an existing \e virtual space
/// \param basespace is the virtual space
/// \param ptrdata is the location data for the base register
/// \param truncSize is the size of the space covered by the base register
/// \param stackGrowth is true if the stack grows "normally" towards address 0
void AddrSpaceManager::addSpacebasePointer(SpacebaseSpace *basespace,const VarnodeData &ptrdata,int4 truncSize,bool stackGrowth)

{
  basespace->setBaseRegister(ptrdata,truncSize,stackGrowth);
}

/// Provide a new specialized resolver for a specific AddrSpace.  The manager takes ownership of resolver.
/// \param spc is the space to which the resolver is associated
/// \param rsolv is the new resolver object
void AddrSpaceManager::insertResolver(AddrSpace *spc,AddressResolver *rsolv)

{
  int4 ind = spc->getIndex();
  while(resolvelist.size() <= ind)
    resolvelist.push_back((AddressResolver *)0);
  if (resolvelist[ind] != (AddressResolver *)0)
    delete resolvelist[ind];
  resolvelist[ind] = rsolv;
}

/// Base destructor class, cleans up AddrSpace pointers which
/// must be explicited created via \e new
AddrSpaceManager::~AddrSpaceManager(void)

{
  for(std::vector<AddrSpace *>::iterator iter=baselist.begin();iter!=baselist.end();++iter) {
    AddrSpace *spc = *iter;
    if (spc->refcount > 1)
      spc->refcount -= 1;
    else
      delete spc;
  }
  for(int4 i=0;i<resolvelist.size();++i) {
    if (resolvelist[i] != (AddressResolver *)0)
      delete resolvelist[i];
  }
  for(int4 i=0;i<splitlist.size();++i)
    delete splitlist[i];	// Delete any join records
}

/// Assign a \e shortcut character to an address space
/// This routine makes use of the desired type of the new space
/// and info about shortcuts for spaces that already exist to
/// pick a unique and consistent character.
/// This is currently invoked by the AddrSpace initialization
/// process.
/// \param tp is the type of the new space
/// \return the shortcut character
char AddrSpaceManager::assignShortcut(spacetype tp) const

{
  char shortcut = 'x';
  switch(tp) {
  case IPTR_CONSTANT:
    shortcut = '#';
    break;
  case IPTR_PROCESSOR:
    shortcut = 'r';
    break;
  case IPTR_SPACEBASE:
    shortcut = 's';
    break;
  case IPTR_INTERNAL:
    shortcut = 'u';
    break;
  case IPTR_FSPEC:
    shortcut = 'f';
    break;
  case IPTR_JOIN:
    shortcut = 'j';
    break;
  case IPTR_IOP:
    shortcut = 'i';
    break;
  }
  //  if ((shortcut >= 'A') && (shortcut <= 'R'))
  //    shortcut |= 0x20;

  for(int4 i=0x61;i<0x7a;++i) {
    int4 j;
    for(j=0;j<baselist.size();++j) {
      if (baselist[j]->getShortcut() == shortcut)
	break;
    }
    if (j == baselist.size()) return shortcut; // Found an open shortcut
    shortcut = (char) i;
    if (shortcut == 'a')
      shortcut = '%';		// Second processor space is usually the register space
  }
  // Could not find a unique shortcut, but we just re-use 'z' as we
  // can always use the long form to specify the address if there are really so many
  // spaces that need to be distinguishable (in the console mode)
  return shortcut;
}

/// All address spaces have a unique name associated with them.
/// This routine retrieves the AddrSpace object based on the
/// desired name.
/// \param nm is the name of the address space
/// \return a pointer to the AddrSpace object
AddrSpace *AddrSpaceManager::getSpaceByName(const string &nm) const

{
  for(int4 i=0;i<baselist.size();++i)
    if (baselist[i]->getName() == nm)
      return baselist[i];
  return (AddrSpace *)0;
}

/// All address spaces have a unique shortcut (ASCII) character
/// assigned to them. This routine retrieves an AddrSpace object
/// given a specific shortcut.
/// \param sc is the shortcut character
/// \return a pointer to an AddrSpace
AddrSpace *AddrSpaceManager::getSpaceByShortcut(char sc) const

{
  for(int4 i=0;i<baselist.size();++i)
    if (baselist[i]->getShortcut() == sc)
      return baselist[i];
  return (AddrSpace *)0;
}

Address AddrSpaceManager::resolveConstant(AddrSpace *spc,uintb val,int4 sz,const Address &point) const

{
  int4 ind = spc->getIndex();
  if (ind < resolvelist.size()) {
    AddressResolver *resolve = resolvelist[ind];
    if (resolve != (AddressResolver *)0)
      return resolve->resolve(val,sz,point);
  }
  val = AddrSpace::addressToByte(val,spc->getWordSize());
  val = spc->wrapOffset(val);
  return Address(spc,val);
}

/// Get the next space in the absolute order of addresses.
/// This ordering is determined by the AddrSpace index.
/// \param spc is the pointer to the space being queried
/// \return the pointer to the next space in absolute order
AddrSpace *AddrSpaceManager::getNextSpaceInOrder(AddrSpace *spc) const
{
  if (spc == (AddrSpace *)0) {
    return baselist[0];
  }
  if (spc == (AddrSpace *) ~((uintp)0)) {
    return (AddrSpace *)0;
  }
  int4 index = spc->getIndex();
  if (index < baselist.size()-1) {
    return baselist[index+1];
  }
  return (AddrSpace *) ~((uintp)0);
}

/// Given a list of memory locations, the \e pieces, either find a pre-existing JoinRecord or
/// create a JoinRecord that represents the logical joining of the pieces.
/// \param pieces if the list memory locations to be joined
/// \param logicalsize of a \e single \e piece join, or zero
/// \return a pointer to the JoinRecord
JoinRecord *AddrSpaceManager::findAddJoin(const std::vector<VarnodeData> &pieces,uint4 logicalsize)

{ // Find a pre-existing split record, or create a new one corresponding to the input -pieces-
  // If -logicalsize- is 0, calculate logical size as sum of pieces
  if (pieces.size() == 0)
    throw LowlevelError("Cannot create a join without pieces");
  if ((pieces.size()==1)&&(logicalsize==0))
    throw LowlevelError("Cannot create a single piece join without a logical size");

  uint4 totalsize;
  if (logicalsize != 0) {
    if (pieces.size() != 1)
      throw LowlevelError("Cannot specify logical size for multiple piece join");
    totalsize = logicalsize;
  }
  else {
    totalsize = 0;
    for(int4 i=0;i<pieces.size();++i) // Calculate sum of the sizes of all pieces
      totalsize += pieces[i].size;
    if (totalsize == 0)
      throw LowlevelError("Cannot create a zero size join");
  }

  JoinRecord testnode;

  testnode.pieces = pieces;
  testnode.unified.size = totalsize;
  std::set<JoinRecord *,JoinRecordCompare>::const_iterator iter;
  iter = splitset.find(&testnode);
  if (iter != splitset.end())		// If already in the std::set
    return *iter;

  JoinRecord *newjoin = new JoinRecord();
  newjoin->pieces = pieces;
  
  uint4 roundsize = (totalsize + 15) & ~((uint4)0xf);	// Next biggest multiple of 16

  newjoin->unified.space = joinspace;
  newjoin->unified.offset = joinallocate;
  joinallocate += roundsize;
  newjoin->unified.size = totalsize;
  splitset.insert(newjoin);
  splitlist.push_back(newjoin);
  return splitlist.back();
}

/// Given a specific \e offset into the \e join address space, recover the JoinRecord that
/// lists the pieces corresponding to that offset.  The offset must originally have come from
/// a JoinRecord returned by \b findAddJoin, otherwise this method throws an exception.
/// \param offset is an offset into the join space
/// \return the JoinRecord for that offset
JoinRecord *AddrSpaceManager::findJoin(uintb offset) const

{ // Find a split record given the unified (join space) offset
  int4 min=0;
  int4 max=splitlist.size()-1;
  while(min<=max) {		// Binary search
    int4 mid = (min+max)/2;
    JoinRecord *rec = splitlist[mid];
    uintb val = rec->unified.offset;
    if (val == offset) return rec;
    if (val < offset)
      min = mid + 1;
    else
      max = mid - 1;
  }
  throw LowlevelError("Unlinked join address");
}

/// std::set the number of passes for a specific AddrSpace before deadcode removal is allowed
/// for that space.
/// \param spcnum is the index of the AddrSpace to change
/// \param delaydelta is the number of rounds to the delay should be std::set to
void AddrSpaceManager::setDeadcodeDelay(int4 spcnum,int4 delaydelta)

{
  baselist[spcnum]->deadcodedelay = delaydelta;
}

/// Mark the named space as truncated from its original size
/// \param tag is a description of the space and how it should be truncated
void AddrSpaceManager::truncateSpace(const TruncationTag &tag)

{
  AddrSpace *spc = getSpaceByName(tag.getName());
  if (spc == (AddrSpace *)0)
    throw LowlevelError("Unknown space in <truncate_space> command: "+tag.getName());
  spc->truncateSpace(tag.getSize());
}

/// This handles the situation where we need to find a logical address to hold the lower
/// precision floating-point value that is stored in a bigger register
/// If the logicalsize (precision) requested matches the -realsize- of the register
/// just return the real address.  Otherwise construct a join address to hold the logical value
/// \param realaddr is the address of the real floating-point register
/// \param realsize is the size of the real floating-point register
/// \param logicalsize is the size (lower precision) size of the logical value
Address AddrSpaceManager::constructFloatExtensionAddress(const Address &realaddr,int4 realsize,
							 int4 logicalsize)
{
  if (logicalsize == realsize)
    return realaddr;
  std::vector<VarnodeData> pieces;
  pieces.push_back(VarnodeData());
  pieces.back().space = realaddr.getSpace();
  pieces.back().offset = realaddr.getOffset();
  pieces.back().size = realsize;

  JoinRecord *join = findAddJoin(pieces,logicalsize);
  return join->getUnified().getAddr();
}

/// This handles the common case, of trying to find a join address given a high location and a low
/// location. This may not return an address in the \e join address space.  It checks for the case
/// where the two pieces are contiguous locations in a mappable space, in which case it just returns
/// the containing address
/// \param translate is the Translate object used to find registers
/// \param hiaddr is the address of the most significant piece to be joined
/// \param hisz is the size of the most significant piece
/// \param loaddr is the address of the least significant piece
/// \param losz is the size of the least significant piece
/// \return an address representing the start of the joined range
Address AddrSpaceManager::constructJoinAddress(const Translate *translate,
					       const Address &hiaddr,int4 hisz,
					       const Address &loaddr,int4 losz)
{
  spacetype hitp = hiaddr.getSpace()->getType();
  spacetype lotp = loaddr.getSpace()->getType();
  bool usejoinspace = true;
  if (((hitp != IPTR_SPACEBASE)&&(hitp != IPTR_PROCESSOR))||
      ((lotp != IPTR_SPACEBASE)&&(lotp != IPTR_PROCESSOR)))
    throw LowlevelError("Trying to join in appropriate locations");
  if ((hitp == IPTR_SPACEBASE)||(lotp == IPTR_SPACEBASE)||
      (hiaddr.getSpace() == getDefaultSpace())||
      (loaddr.getSpace() == getDefaultSpace()))
    usejoinspace = false;
  if (hiaddr.isContiguous(hisz,loaddr,losz)) { // If we are contiguous
    if (!usejoinspace) { // and in a mappable space, just return the earliest address
      if (hiaddr.isBigEndian())
	return hiaddr;
      return loaddr;
    }
    else {			// If we are in a non-mappable (register) space, check to see if a parent register exists
      if (hiaddr.isBigEndian()) {
	if (translate->getRegisterName(hiaddr.getSpace(),hiaddr.getOffset(),(hisz+losz)).size() != 0)
	  return hiaddr;
      }
      else {
	if (translate->getRegisterName(loaddr.getSpace(),loaddr.getOffset(),(hisz+losz)).size() != 0)
	  return loaddr;
      }
    }
  }
  // Otherwise construct a formal JoinRecord
  std::vector<VarnodeData> pieces;
  pieces.push_back(VarnodeData());
  pieces.push_back(VarnodeData());
  pieces[0].space = hiaddr.getSpace();
  pieces[0].offset = hiaddr.getOffset();
  pieces[0].size = hisz;
  pieces[1].space = loaddr.getSpace();
  pieces[1].offset = loaddr.getOffset();
  pieces[1].size = losz;
  JoinRecord *join = findAddJoin(pieces,0);
  return join->getUnified().getAddr();
}

/// This constructs only a shell for the Translate object.  It
/// won't be usable until it is initialized for a specific processor
/// The main entry point for this is the Translate::initialize method,
/// which must be overridden by a derived class
Translate::Translate(void)

{
  target_isbigendian = false;
  unique_base=0;
  alignment = 1;
}

/// If no floating-point format objects were registered by the \b initialize method, this
/// method will fill in some suitable default formats.  These defaults are based on
/// the 4-byte and 8-byte encoding specified by the IEEE 754 standard.
void Translate::setDefaultFloatFormats(void)

{
  if (floatformats.empty()) {	// Default IEEE 754 float formats
    floatformats.push_back(FloatFormat(4));
    floatformats.push_back(FloatFormat(8));
  }
}

/// The pcode model for floating point encoding assumes that a
/// consistent encoding is used for all values of a given size.
/// This routine fetches the FloatFormat object given the size,
/// in bytes, of the desired encoding.
/// \param size is the size of the floating-point value in bytes
/// \return a pointer to the floating-point format
const FloatFormat *Translate::getFloatFormat(int4 size) const

{
  std::vector<FloatFormat>::const_iterator iter;

  for(iter=floatformats.begin();iter!=floatformats.end();++iter) {
    if ((*iter).getSize() == size)
      return &(*iter);
  }
  return (const FloatFormat *)0;
}

/// A convenience method for passing around pcode operations via
/// XML.  A single pcode operation is parsed from an XML tag and
/// returned to the application via the PcodeEmit::dump method.
/// \param el is the pcode operation XML tag
/// \param manage is the AddrSpace manager object of the associated processor
void PcodeEmit::restoreXmlOp(const Element *el,const AddrSpaceManager *manage)

{ // Read a raw pcode op from DOM (and dump it)
  int4 opcode;
  VarnodeData outvar;
  VarnodeData invar[30];
  VarnodeData *outptr;

  std::istringstream i(el->getAttributeValue("code"));
  i >> opcode;
  const List &list(el->getChildren());
  List::const_iterator iter = list.begin();
  Address pc = Address::restoreXml(*iter,manage);
  ++iter;
  if ((*iter)->getName() == "void") 
    outptr = (VarnodeData *)0;
  else {
    outvar.restoreXml(*iter,manage);
    outptr = &outvar;
  }
  ++iter;
  int4 isize = 0;
  while(iter != list.end() && isize < 30) {
    if ((*iter)->getName() == "spaceid") {
      invar[isize].space = manage->getConstantSpace();
      invar[isize].offset = (uintb)(uintp)manage->getSpaceByName( (*iter)->getAttributeValue("name") );
      invar[isize].size = sizeof(void *);
    }
    else
      invar[isize].restoreXml(*iter,manage);
    isize += 1;
    ++iter;
  }
  dump(pc,(OpCode)opcode,outptr,invar,isize);
}

/// A Helper function for PcodeEmit::restorePackedOp that reads an unsigned offset from a packed stream
/// \param ptr is a pointer into a packed byte stream
/// \param off is where the offset read from the stream is stored
/// \return a pointer to the next unconsumed byte of the stream
const uint1 *PcodeEmit::unpackOffset(const uint1 *ptr,uintb &off)

{
  uintb res = 0;
  int4 shift;
  for(shift=0;shift<67;shift+=6) {
    uint1 val = *ptr++;
    if (val == end_tag) {
      off = res;
      return ptr;
    }
    uintb bits = ((uintb)(val-0x20))<<shift;
    res |= bits;
  }
  throw LowlevelError("Bad packed offset");
}

/// A Helper function for PcodeEmit::restorePackedOp that reads a varnode from a packed stream
/// \param ptr is a pointer into a packed byte stream
/// \param v is the VarnodeData object being filled in by the stream
/// \param manage is the AddrSpace manager object of the associated processor
/// \return a pointer to the next unconsumed byte of the stream
const uint1 *PcodeEmit::unpackVarnodeData(const uint1 *ptr,VarnodeData &v,const AddrSpaceManager *manage)

{
  uint1 tag = *ptr++;
  if (tag == addrsz_tag) {
    int4 spcindex = (int4)(*ptr++ - 0x20);
    v.space = manage->getSpace(spcindex);
    ptr = unpackOffset(ptr,v.offset);
    v.size = (uint4)(*ptr++ - 0x20);
  }
  else if (tag == spaceid_tag) {
    v.space = manage->getConstantSpace();
    int4 spcindex = (int4)(*ptr++ - 0x20);
    v.offset = (uintb)(uintp)manage->getSpace( spcindex );
    v.size = sizeof(void *);
  }
  else
    throw LowlevelError("Bad packed VarnodeData");
  return ptr;
}

/// A convenience method for passing around pcode operations via a special packed format.
/// A single pcode operation is parsed from a byte stream and returned to the application
/// via the PcodeEmit::dump method.
/// \param addr is the address of the instruction that generated this pcode
/// \param ptr is a pointer into a packed byte stream
/// \param manage is the AddrSpace manager object of the associated processor
/// \return a pointer to the next unconsumed byte of the stream
const uint1 *PcodeEmit::restorePackedOp(const Address &addr,const uint1 *ptr,const AddrSpaceManager *manage)

{
  int4 opcode;
  VarnodeData outvar;
  VarnodeData invar[30];
  VarnodeData *outptr;

  ptr += 1;			// Consume the -op- tag
  opcode = (int4)(*ptr++ - 0x20);	// Opcode
  if (*ptr == void_tag) {
    ptr += 1;
    outptr = (VarnodeData *)0;
  }
  else {
    ptr = unpackVarnodeData(ptr,outvar,manage);
    outptr = &outvar;
  }
  int4 isize = 0;
  while(*ptr != end_tag) {
    ptr = unpackVarnodeData(ptr,invar[isize],manage);
    isize += 1;
  }
  ptr += 1;			// Consume the end tag
  dump(addr,(OpCode)opcode,outptr,invar,isize);
  return ptr;
}
}
