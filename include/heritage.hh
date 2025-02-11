/* ###
 * IP: GHIDRA
 * NOTE: Phi placement and renaming based on ACM journal articles
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
/// \file heritage.hh
/// \brief Utilities for building Static Single Assignment (SSA) form 

#ifndef __CPUI_HERITAGE__
#define __CPUI_HERITAGE__

#include "block.hh"

#include <map>

namespace GhidraDec {

/// Container holding the stack system for the renaming algorithm.  Every disjoint address
/// range (indexed by its initial address) maps to its own Varnode stack.
typedef map<Address,vector<Varnode *> > VariableStack;

/// \brief Label for describing extent of address range that has been heritaged
struct SizePass {
  int4 size;			///< Size of the range (in bytes)
  int4 pass;			///< Pass when the range was heritaged
};

/// \brief Map object for keeping track of which address ranges have been heritaged
///
/// We keep track of a fairly fine grained description of when each address range
/// was entered in SSA form, refered to as \b heritaged or, for Varnode objects,
/// no longer \b free.  An address range is added using the add() method, which includes
/// the particular pass when it was entered.  The map can be queried using findPass()
/// that informs the caller whether the address has been heritaged and if so in which pass.
class LocationMap {
public:
  /// Iterator into the main map
  typedef map<Address,SizePass>::iterator iterator;
private:
  map<Address,SizePass> themap;	///< Heritaged addresses mapped to range size and pass number
public:
  iterator add(Address addr,int4 size,int4 pass,int4 &intersect); ///< Mark new address as \b heritaged
  iterator find(Address addr);			      ///< Look up if/how given address was heritaged
  int4 findPass(Address addr) const;		      ///< Look up if/how given address was heritaged
  void erase(iterator iter) { themap.erase(iter); }   ///< Remove a particular entry from the map
  iterator begin(void) { return themap.begin(); }     ///< Get starting iterator over heritaged ranges
  iterator end(void) { return themap.end(); }	      ///< Get ending iterator over heritaged ranges
  void clear(void) { themap.clear(); }		      ///< Clear the map of heritaged ranges
};

/// \brief Priority queue for the phi-node (MULTIEQUAL) placement algorithm
///
/// A \e work-list for basic blocks used during phi-node placement.  Implemented as
/// a set of stacks with an associated priority.  Blocks are placed in the \e queue
/// with an associated \e priority (or depth) using the insert() method.  The current
/// highest priority block is retrieved with the extract() method.
class PriorityQueue {
  vector<vector<FlowBlock *> > queue; ///< An array of \e stacks, indexed by priority
  int4 curdepth;		      ///< The current highest priority index with active blocks
public:
  PriorityQueue(void) { curdepth = -2; } ///< Constructor
  void reset(int4 maxdepth);		 ///< Reset to an empty queue
  void insert(FlowBlock *bl,int4 depth); ///< Insert a block into the queue given its priority
  FlowBlock *extract(void);		 ///< Retrieve the highest priority block
  bool empty(void) const { return (curdepth==-1); } ///< Return \b true if \b this queue is empty
};

class Funcdata;

/// \brief Information about heritage passes performed for a specific address space
///
/// For a particular address space, this keeps track of:
///   - how long to delay heritage
///   - how long to delay dead code removal
///   - whether dead code has been removed (for this space)
///   - have warnings been issued
class HeritageInfo {
  friend class Heritage;
  AddrSpace *space;		///< The address space \b this record describes
  int4 delay;			///< How many passes to delay heritage of this space
  int4 deadcodedelay;		///< How many passes to delay deadcode removal of this space
  int4 deadremoved;		///< >0 if Varnodes in this space have been eliminated
  bool warningissued;		///< \b true if warning issued previously
  HeritageInfo(AddrSpace *spc,int4 dl,int4 dcdl) {
    space=spc; delay=dl; deadcodedelay=dcdl; deadremoved=0; warningissued=false; } ///< Constructor
};

/// \brief Manage the construction of Static Single Assignment (SSA) form
///
/// With a specific function (Funcdata), this class links the Varnode and
/// PcodeOp objects into the formal data-flow graph structure, SSA form.
/// The full structure can be built over multiple passes. In particular,
/// this allows register data-flow to be analyzed first, and then stack
/// locations can be discovered and promoted to first-class Varnodes in
/// a second pass.
///
/// Varnodes for which it is not known whether they are written to by a
/// PcodeOp are referred to as \b free.  The method heritage() performs
/// a \e single \e pass of constructing SSA form, collecting any \e eligible
/// free Varnodes for the pass and linking them in to the data-flow. A
/// Varnode is considered eligible for a given pass generally based on its
/// address space (see HeritageInfo), which is the main method for delaying
/// linking for stack locations until they are all discovered. In
/// principle a Varnode can be discovered very late and still get linked
/// in on a subsequent pass. Linking causes Varnodes to gain new descendant
/// PcodeOps, which has impact on dead code elimination (see LocationMap).
///
/// The two big aspects of SSA construction are phi-node placement, performed
/// by placeMultiequals(), and the \e renaming algorithm, performed by rename().
/// The various guard* methods are concerned with labeling analyzing
/// data-flow across function calls, STORE, and LOAD operations.
///
/// The phi-node placement algorithm is from (preprint?)
/// "The Static Single Assignment Form and its Computation"
/// by Gianfranco Bilardi and Keshav Pingali, July 22, 1999
///
/// The renaming algorithm taken from
/// "Efficiently computing static single assignment form and the
///  control dependence graph."
/// R. Cytron, J. Ferrante, B. K. Rosen, M. N. Wegman, and F. K. Zadeck
/// ACM Transactions on Programming Languages and Systems,
/// 13(4):451-490, October 1991
class Heritage {
  /// Extra boolean properties on basic blocks for the Augmented Dominator Tree
  enum heritage_flags {
    boundary_node = 1,		///< Augmented Dominator Tree boundary node
    mark_node = 2,		///< Node has already been in queue
    merged_node = 4		///< Node has already been merged
  };
  Funcdata *fd;		        ///< The function \b this is controlling SSA construction 
  LocationMap globaldisjoint;	///< Disjoint cover of every heritaged memory location
  LocationMap disjoint;		///< Disjoint cover of memory locations currently being heritaged
  vector<vector<FlowBlock *> > domchild; ///< Parent->child edges in dominator tree
  vector<vector<FlowBlock *> > augment; ///< Augmented edges
  vector<uint4> flags;		///< Block properties for phi-node placement algorithm
  vector<int4> depth;		///< Dominator depth of individual blocks
  int4 maxdepth;		///< Maximum depth of the dominator tree
  int4 pass;			///< Current pass being executed

  PriorityQueue pq;		///< Priority queue for phi-node placement
  vector<FlowBlock *> merge;	///< Calculate merge points (blocks containing phi-nodes)
  vector<HeritageInfo> infolist; ///< Heritage status for individual address spaces
  void clearInfoList(void);	 ///< Reset heritage status for all address spaces

  /// \brief Get the heritage status for the given address space
  HeritageInfo *getInfo(AddrSpace *spc) { return &(infolist[spc->getIndex()]); }

  /// \brief Get the heriage status for the given address space
  const HeritageInfo *getInfo(AddrSpace *spc) const { return &(infolist[spc->getIndex()]); }

  void splitJoinLevel(vector<Varnode *> &lastcombo,vector<Varnode *> &nextlev,JoinRecord *joinrec);
  void splitJoinRead(Varnode *vn,JoinRecord *joinrec);
  void splitJoinWrite(Varnode *vn,JoinRecord *joinrec);
  void floatExtensionRead(Varnode *vn,JoinRecord *joinrec);
  void floatExtensionWrite(Varnode *vn,JoinRecord *joinrec);
  void processJoins(void);
  void buildADT(void);		///< Build the augmented dominator tree
  int4 collect(Address addr,int4 size,vector<Varnode *> &read,vector<Varnode *> &write,vector<Varnode *> &input) const;
  bool callOpIndirectEffect(const Address &addr,int4 size,PcodeOp *op) const;
  Varnode *normalizeReadSize(Varnode *vn,const Address &addr,int4 size);
  Varnode *normalizeWriteSize(Varnode *vn,const Address &addr,int4 size);
  Varnode *concatPieces(const vector<Varnode *> &vnlist,PcodeOp *insertop,Varnode *finalvn);
  void splitPieces(const vector<Varnode *> &vnlist,PcodeOp *insertop,const Address &addr,int4 size,Varnode *startvn);
  void guard(const Address &addr,int4 size,vector<Varnode *> &read,vector<Varnode *> &write,vector<Varnode *> &inputvars);
  void guardInput(const Address &addr,int4 size,vector<Varnode *> &input);
  void guardCalls(uint4 flags,const Address &addr,int4 size,vector<Varnode *> &write);
  void guardStores(const Address &addr,int4 size,vector<Varnode *> &write);
  void guardReturns(uint4 flags,const Address &addr,int4 size,vector<Varnode *> &write);
  //  void guardLoads(uint4 flags,const Address &addr,int4 size,vector<Varnode *> &write);
  static void buildRefinement(vector<int4> &refine,const Address &addr,int4 size,const vector<Varnode *> &vnlist);
  void splitByRefinement(Varnode *vn,const Address &addr,const vector<int4> &refine,vector<Varnode *> &split);
  void refineRead(Varnode *vn,const Address &addr,const vector<int4> &refine,vector<Varnode *> &newvn);
  void refineWrite(Varnode *vn,const Address &addr,const vector<int4> &refine,vector<Varnode *> &newvn);
  void refineInput(Varnode *vn,const Address &addr,const vector<int4> &refine,vector<Varnode *> &newvn);
  void remove13Refinement(vector<int4> &refine);
  bool refinement(const Address &addr,int4 size,const vector<Varnode *> &readvars,const vector<Varnode *> &writevars,const vector<Varnode *> &inputvars);
  void visitIncr(FlowBlock *qnode,FlowBlock *vnode);
  void calcMultiequals(const vector<Varnode *> &write);
  void renameRecurse(BlockBasic *bl,VariableStack &varstack);
  void bumpDeadcodeDelay(Varnode *vn);
public:
  Heritage(Funcdata *data);	///< Constructor

  /// \brief Get the pass number when the given address was heritaged
  ///
  /// \param addr is the given address
  /// \return the pass number or -1 if the address has not been heritaged
  int4 heritagePass(const Address &addr) const { return globaldisjoint.findPass(addr); }
  int4 numHeritagePasses(AddrSpace *spc) const;
  void seenDeadCode(AddrSpace *spc); ///< Inform system of dead code removal in given space 
  int4 getDeadCodeDelay(AddrSpace *spc) const; ///< Get pass delay for heritaging the given space
  void setDeadCodeDelay(AddrSpace *spc,int4 delay); ///< Set delay for a specific space
  bool deadRemovalAllowed(AddrSpace *spc) const;    ///< Return \b true if it is \e safe to remove dead code
  bool deadRemovalAllowedSeen(AddrSpace *spc);
  void buildInfoList(void);	                    ///< Initialize information for each space
  void forceRestructure(void) { maxdepth = -1; }    ///< Force regeneration of basic block structures
  void clear(void);				    ///< Reset all analysis of heritage
  void placeMultiequals(void);
  void rename(void);
  void heritage(void);				    ///< Perform one pass of heritage
};

} // namespace GhidraDec

#endif
