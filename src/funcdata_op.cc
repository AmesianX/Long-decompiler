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
#include "funcdata.hh"
#include "flow.hh"

namespace GhidraDec {
// Funcdata members pertaining directly to ops

/// \param op is the given PcodeOp
/// \param opc is the op-code to std::set
void Funcdata::opSetOpcode(PcodeOp *op,OpCode opc)

{
#ifdef OPACTION_DEBUG
  if (opactdbg_active)
    debugModCheck(op);
#endif
  obank.changeOpcode(op, glb->inst[opc] );
}

/// \param op is the given CPUI_RETURN op
/// \param flag is one of \e halt, \e badinstruction, \e unimplemented, \e noreturn, or \e missing.
void Funcdata::opMarkHalt(PcodeOp *op,uint4 flag)

{
  if (op->code() != CPUI_RETURN)
    throw LowlevelError("Only RETURN pcode ops can be marked as halt");
  flag &= (PcodeOp::halt|PcodeOp::badinstruction|
	   PcodeOp::unimplemented|PcodeOp::noreturn|
	   PcodeOp::missing);
  if (flag == 0)
    throw LowlevelError("Bad halt flag");
  op->setFlag(flag);
}

/// The output Varnode becomes \e free but is not immediately deleted.
/// \param op is the given PcodeOp
void Funcdata::opUnsetOutput(PcodeOp *op)

{
  Varnode *vn;

  vn = op->getOut();
  if (vn == (Varnode *)0) return; // Nothing to do
#ifdef OPACTION_DEBUG
  if (opactdbg_active)
    debugModCheck(op);
#endif
  op->setOutput((Varnode *)0); // This must come before make_free
  vbank.makeFree(vn);
  vn->clearCover();
}

/// \param op is the specific PcodeOp
/// \param vn is the output Varnode to std::set
void Funcdata::opSetOutput(PcodeOp *op,Varnode *vn)

{
  if (vn == op->getOut()) return; // Already std::set to this vn
#ifdef OPACTION_DEBUG
  if (opactdbg_active)
    debugModCheck(op);
#endif
  if (op->getOut() != (Varnode *)0) {
    opUnsetOutput(op);
  }

  if (vn->getDef() != (PcodeOp *)0)	// If this varnode is already an output
    opUnsetOutput(vn->getDef());
  vn = vbank.setDef(vn,op);
  setVarnodeProperties(vn);
  op->setOutput(vn);
}

/// The input Varnode is unlinked from the op.
/// \param op is the given PcodeOp
/// \param slot is the input slot to clear
void Funcdata::opUnsetInput(PcodeOp *op,int4 slot)

{
  Varnode *vn = op->getIn(slot);

  vn->eraseDescend(op);
  op->clearInput(slot);		// Must be called AFTER descend_erase
}

/// \param op is the given PcodeOp
/// \param vn is the operand Varnode to std::set
/// \param slot is the input slot where the Varnode is placed
void Funcdata::opSetInput(PcodeOp *op,Varnode *vn,int4 slot)

{
  if (vn == op->getIn(slot)) return; // Already std::set to this vn
  if (vn->isConstant()) {	// Constants should have only one descendant
    if (!vn->hasNoDescend())
      if (!vn->isSpacebase()) {	// Unless they are a spacebase
	Varnode *cvn = newConstant(vn->getSize(),vn->getOffset());
	cvn->copySymbol(vn);
	vn = cvn;
      }
  }
#ifdef OPACTION_DEBUG
  if (opactdbg_active)
    debugModCheck(op);
#endif
  if (op->getIn(slot) != (Varnode *)0)
    opUnsetInput(op,slot);

  vn->addDescend(op);		// Add this op to std::list of vn's descendants
  op->setInput(vn,slot);	// op must be up to date AFTER calling descend_add
}

/// This is convenience method that is more efficient than call opSetInput() twice.
/// \param op is the given PcodeOp
/// \param slot1 is the first input slot being switched
/// \param slot2 is the second input slot
void Funcdata::opSwapInput(PcodeOp *op,int4 slot1,int4 slot2)

{
#ifdef OPACTION_DEBUG
  if (opactdbg_active)
    debugModCheck(op);
#endif
  Varnode *tmp = op->getIn(slot1);
  op->setInput(op->getIn(slot2),slot1);
  op->setInput(tmp,slot2);
}

/// \brief Insert the given PcodeOp at specific point in a basic block
///
/// The PcodeOp is removed from the \e dead std::list and is inserted \e immediately before
/// the specified iterator.
/// \param op is the given PcodeOp
/// \param bl is the basic block being inserted into
/// \param iter indicates exactly where the op is inserted
void Funcdata::opInsert(PcodeOp *op,BlockBasic *bl,std::list<PcodeOp *>::iterator iter)

{
#ifdef OPACTION_DEBUG
  if (opactdbg_active)
    debugModCheck(op);
#endif
  obank.markAlive(op);
  bl->insert(iter,op);
}

/// The op is taken out of its basic block and put into the dead std::list. If the removal
/// is permanent the input and output Varnodes should be unset.
/// \param op is the given PcodeOp
void Funcdata::opUninsert(PcodeOp *op)

{
  #ifdef OPACTION_DEBUG
  if (opactdbg_active)
    debugModCheck(op);
#endif
  obank.markDead(op);
  op->getParent()->removeOp(op);
}

/// The op is extricated from all its Varnode connections to the functions data-flow and
/// removed from its basic block. This will \e not change block connections.  The PcodeOp
/// objects remains in the \e dead std::list.
/// \param op is the given PcodeOp
void Funcdata::opUnlink(PcodeOp *op)

{
  int4 i;
#ifdef OPACTION_DEBUG
  if (opactdbg_active)
    debugModCheck(op);
#endif
				// Unlink input and output varnodes
  opUnsetOutput(op);
  for(i=0;i<op->numInput();++i)
    opUnsetInput(op,i);
  if (op->getParent() != (BlockBasic *)0) // Remove us from basic block
    opUninsert(op);
}

/// All input and output Varnodes to the op are destroyed (their object resources freed),
/// and the op is permanently moved to the \e dead std::list.
/// To call this routine, make sure that either:
///   - The op has no output
///   - The op's output has no descendants
///   - or all descendants of output are also going to be destroyed
///
/// \param op is the given PcodeOp
void Funcdata::opDestroy(PcodeOp *op)

{
  #ifdef OPACTION_DEBUG
  if (opactdbg_active)
    debugModCheck(op);
#endif

  if (op->getOut() != (Varnode *)0)
    destroyVarnode(op->getOut());
  for(int4 i=0;i<op->numInput();++i) {
    Varnode *vn = op->getIn(i);
    if (vn != (Varnode *)0)
      opUnsetInput(op,i);
  }
  if (op->getParent() != (BlockBasic *)0) {
    obank.markDead(op);
    op->getParent()->removeOp(op);
  }
}

/// This is a specialized routine for deleting an op during flow generation that has
/// been replaced by something else.  The op is expected to be \e dead with none of its inputs
/// or outputs linked to anything else.  Both the PcodeOp and all the input/output Varnodes are destroyed.
/// \param op is the given PcodeOp
void Funcdata::opDestroyRaw(PcodeOp *op)

{
  for(int4 i=0;i<op->numInput();++i)
    destroyVarnode(op->getIn(i));
  if (op->getOut() != (Varnode *)0)
    destroyVarnode(op->getOut());
  obank.destroy(op);
}

/// All previously existing input Varnodes are unset.  The input slots for the
/// op are resized and then filled in from the specified array.
/// \param op is the given PcodeOp to std::set
/// \param vvec is the specified array of new input Varnodes
void Funcdata::opSetAllInput(PcodeOp *op,const std::vector<Varnode *> &vvec)

{
  int4 i;

#ifdef OPACTION_DEBUG
  if (opactdbg_active)
    debugModCheck(op);
#endif
  for(i=0;i<op->numInput();++i)
    if (op->getIn(i) != (Varnode *)0)
      opUnsetInput(op,i);

  op->setNumInputs( vvec.size() );

  for(i=0;i<op->numInput();++i)
    opSetInput(op,vvec[i],i);
}

/// The Varnode in the specified slot is unlinked from the op and the slot itself
/// is removed. The slot index for any remaining input Varnodes coming after the
/// specified slot is decreased by one.
/// \param op is the given PcodeOp
/// \param slot is the index of the specified slot to remove
void Funcdata::opRemoveInput(PcodeOp *op,int4 slot)

{
#ifdef OPACTION_DEBUG
  if (opactdbg_active)
    debugModCheck(op);
#endif
  opUnsetInput(op,slot);
  op->removeInput(slot);
}

/// The given Varnode is std::set into the given operand slot. Any existing input Varnodes
/// with slot indices equal to or greater than the specified slot are pushed into the
/// next slot.
/// \param op is the given PcodeOp
/// \param vn is the given Varnode to insert
/// \param slot is the input index to insert at
void Funcdata::opInsertInput(PcodeOp *op,Varnode *vn,int4 slot)

{
#ifdef OPACTION_DEBUG
  if (opactdbg_active)
    debugModCheck(op);
#endif
  op->insertInput(slot);
  opSetInput(op,vn,slot);
}

/// \param inputs is the number of operands the new op will have
/// \param pc is the Address associated with the new op
/// \return the new PcodeOp
PcodeOp *Funcdata::newOp(int4 inputs,const Address &pc)

{
  return obank.create(inputs,pc);
}

/// This method is typically used for cloning.
/// \param inputs is the number of operands the new op will have
/// \param sq is the sequence number (Address and sub-index) of the new op
/// \return the new PcodeOp
PcodeOp *Funcdata::newOp(int4 inputs,const SeqNum &sq)

{
  return obank.create(inputs,sq);
}

/// The given PcodeOp is inserted \e immediately before the \e follow op except:
///  - MULTIEQUALS in a basic block all occur first
///  - INDIRECTs occur immediately before their op
///  - a branch op must be the very last op in a basic block
///
/// \param op is the given PcodeOp to insert
/// \param follow is the op to insert before
void Funcdata::opInsertBefore(PcodeOp *op,PcodeOp *follow)

{
  std::list<PcodeOp *>::iterator iter = follow->getBasicIter();
  BlockBasic *parent = follow->getParent();

  if (op->code() != CPUI_INDIRECT) {
  // There should not be an INDIRECT immediately preceding op
    PcodeOp *previousop;
    while(iter != parent->beginOp()) {
      --iter;
      previousop = *iter;
      if (previousop->code() != CPUI_INDIRECT) {
	++iter;
	break;
      }
    }
  }
  opInsert(op,parent,iter);
}

/// The given PcodeOp is inserted \e immediately after the \e prev op except:
///  - MULTIEQUALS in a basic block all occur first
///  - INDIRECTs occur immediately before their op
///  - a branch op must be the very last op in a basic block
///
/// \param op is the given PcodeOp to insert
/// \param prev is the op to insert after
void Funcdata::opInsertAfter(PcodeOp *op,PcodeOp *prev)

{
  if (prev->isMarker()) {
    if (prev->code() == CPUI_INDIRECT) {
      Varnode *invn = prev->getIn(1);
      if (invn->getSpace()->getType()==IPTR_IOP)
	prev = PcodeOp::getOpFromConst(invn->getAddr()); // Store or call
    }
  }
  std::list<PcodeOp *>::iterator iter = prev->getBasicIter();
  BlockBasic *parent = prev->getParent();

  iter++;

  if (op->code() != CPUI_MULTIEQUAL) {
  // There should not be a MULTIEQUAL immediately after op
    PcodeOp *nextop;
    while(iter != parent->endOp()) {
      nextop = *iter;
      ++iter;
      if (nextop->code() != CPUI_MULTIEQUAL) {
	--iter;
	break;
      }
    }
  }
  opInsert(op,prev->getParent(),iter);
}

/// The given PcodeOp is inserted as the \e first op in the basic block except:
///  - MULTIEQUALS in a basic block all occur first
///  - INDIRECTs occur immediately before their op
///  - a branch op must be the very last op in a basic block
///
/// \param op is the given PcodeOp to insert
/// \param bl is the basic block to insert into
void Funcdata::opInsertBegin(PcodeOp *op,BlockBasic *bl)

{
  std::list<PcodeOp *>::iterator iter = bl->beginOp();
  
  if (op->code()!=CPUI_MULTIEQUAL) {
    while(iter != bl->endOp()) {
      if ((*iter)->code() != CPUI_MULTIEQUAL)
	break;
      ++iter;
    }
  }
  opInsert(op,bl,iter);
}

/// The given PcodeOp is inserted as the \e last op in the basic block except:
///  - MULTIEQUALS in a basic block all occur first
///  - INDIRECTs occur immediately before their op
///  - a branch op must be the very last op in a basic block
///
/// \param op is the given PcodeOp to insert
/// \param bl is the basic block to insert into
void Funcdata::opInsertEnd(PcodeOp *op,BlockBasic *bl)

{
  std::list<PcodeOp *>::iterator iter = bl->endOp();

  if (iter != bl->beginOp()) {
    --iter;
    if (!(*iter)->isFlowBreak())
      ++iter;
  }
  opInsert(op,bl,iter);
}

/// \brief Create an INT_ADD PcodeOp calculating an offset to the \e spacebase register.
///
/// The \e spacebase register is looked up for the given address space, or an optional previously
/// existing register Varnode can be provided. An insertion point op must be provided,
/// and newly generated ops can come either before or after this insertion point.
/// \param spc is the given address space
/// \param off is the offset to calculate relative to the \e spacebase register
/// \param op is the insertion point PcodeOp
/// \param stackptr is the \e spacebase register Varnode (if available)
/// \param insertafter is \b true if new ops are inserted \e after the insertion point
/// \return the \e unique space Varnode holding the calculated offset
Varnode *Funcdata::createStackRef(AddrSpace *spc,uintb off,PcodeOp *op,Varnode *stackptr,bool insertafter)

{
  PcodeOp *addop;
  Varnode *addout;
  int4 addrsize;

  // Calculate CURRENT stackpointer as base for relative offset
  if (stackptr == (Varnode *)0)	// If we are not reusing an old reference to the stack pointer
    stackptr = newSpacebasePtr(spc); // create a new reference
  addrsize = stackptr->getSize();
  addop = newOp(2,op->getAddr());
  opSetOpcode(addop,CPUI_INT_ADD);
  addout = newUniqueOut(addrsize,addop);
  opSetInput(addop,stackptr,0);
  off = AddrSpace::byteToAddress(off,spc->getWordSize());
  opSetInput(addop,newConstant(addrsize,off),1);
  if (insertafter)
    opInsertAfter(addop,op);
  else
    opInsertBefore(addop,op);

  AddrSpace *containerid = spc->getContain();
  SegmentOp *segdef = glb->userops.getSegmentOp(containerid->getIndex());

  if (segdef != (SegmentOp *)0) {
    PcodeOp *segop = newOp(3,op->getAddr());
    opSetOpcode(segop,CPUI_SEGMENTOP);
    Varnode *segout = newUniqueOut(containerid->getAddrSize(),segop);
    opSetInput(segop,newVarnodeSpace(containerid),0);
    opSetInput(segop,newConstant(segdef->getBaseSize(),0),1);
    opSetInput(segop,addout,2);
    opInsertAfter(segop,addop); // Make sure -segop- comes after -addop- regardless if before/after -op-
    addout = segout;
  }

  return addout;
}

/// \brief Create a STORE expression at an offset relative to a \e spacebase register for a given address space
///
/// The \e spacebase register is looked up for the given address space. An insertion point
/// op must be provided, and newly generated ops can come either before or after this insertion point.
/// The Varnode value being stored must still be std::set on the returned PcodeOp.
/// \param spc is the given address space
/// \param off is the offset to calculate relative to the \e spacebase register
/// \param op is the insertion point PcodeOp
/// \param insertafter is \b true if new ops are inserted \e after the insertion point
/// \return the STORE PcodeOp
PcodeOp *Funcdata::opStackStore(AddrSpace *spc,uintb off,PcodeOp *op,bool insertafter)

{ // Create pcode sequence that stores a value at an offset relative to a spacebase
  // -off- is the offset, -size- is the size of the value
  // The sequence is inserted before/after -op- based on whether -insertafter- is false/true
  // Return the store op
  Varnode *addout;
  PcodeOp *storeop;

  // Calculate CURRENT stackpointer as base for relative offset
  addout = createStackRef(spc,off,op,(Varnode *)0,insertafter);

  storeop = newOp(3,op->getAddr());
  opSetOpcode(storeop,CPUI_STORE);

  opSetInput(storeop,newVarnodeSpace(spc->getContain()),0);
  opSetInput(storeop,addout,1);
  opInsertAfter(storeop,addout->getDef()); // STORE comes after stack building op, regardless of -insertafter-
  return storeop;
}

/// \brief Create a LOAD expression at an offset relative to a \e spacebase register for a given address space
///
/// The \e spacebase register is looked up for the given address space, or an optional previously
/// existing register Varnode can be provided. An insertion point op must be provided,
/// and newly generated ops can come either before or after this insertion point.
/// \param spc is the given address space
/// \param off is the offset to calculate relative to the \e spacebase register
/// \param sz is the size of the desire LOAD in bytes
/// \param op is the insertion point PcodeOp
/// \param stackref is the \e spacebase register Varnode (if available)
/// \param insertafter is \b true if new ops are inserted \e after the insertion point
/// \return the \e unique space Varnode holding the result of the LOAD
Varnode *Funcdata::opStackLoad(AddrSpace *spc,uintb off,uint4 sz,PcodeOp *op,Varnode *stackref,bool insertafter)

{
    Varnode *addout = createStackRef(spc,off,op,stackref,insertafter);
    PcodeOp *loadop = newOp(2,op->getAddr());
    opSetOpcode(loadop,CPUI_LOAD);
    opSetInput(loadop,newVarnodeSpace(spc->getContain()),0);
    opSetInput(loadop,addout,1);
    Varnode *res = newUniqueOut(sz,loadop);
    opInsertAfter(loadop,addout->getDef()); // LOAD comes after stack building op, regardless of -insertafter-
    return res;
}

/// Make a clone of the given PcodeOp, copying control-flow properties as well.  The data-type
/// is \e not cloned.
/// \param op is the PcodeOp to clone
/// \param seq is the (possibly custom) sequence number to associate with the clone
/// \return the cloned PcodeOp
PcodeOp *Funcdata::cloneOp(const PcodeOp *op,const SeqNum &seq)

{
  PcodeOp *newop = newOp(op->numInput(),seq);
  opSetOpcode(newop,op->code());
  uint4 flags = op->flags & (PcodeOp::startmark | PcodeOp::startbasic);
  opSetFlag(newop,flags);
  if (op->getOut() != (Varnode *)0)
    opSetOutput(newop,cloneVarnode(op->getOut()));
  for(int4 i=0;i<op->numInput();++i)
    opSetInput(newop,cloneVarnode(op->getIn(i)),i);
  return newop;
}

/// Return the CPUI_RETURN op with the most specialized data-type, which is not
/// dead and is not a special halt. If HighVariables are not available, just
/// return the first CPUI_RETURN op.
/// \return the representative CPUI_RETURN op or NULL
PcodeOp *Funcdata::canonicalReturnOp(void) const

{
  bool hasnohigh = !isHighOn();
  PcodeOp *res = (PcodeOp *)0;
  Datatype *bestdt = (Datatype *)0;
  std::list<PcodeOp *>::const_iterator iter,iterend;
  iterend = endOp(CPUI_RETURN);
  for(iter=beginOp(CPUI_RETURN);iter!=iterend;++iter) {
    PcodeOp *retop = *iter;
    if (retop->isDead()) continue;
    if (retop->getHaltType()!=0) continue;
    if (retop->numInput() > 1) {
      if (hasnohigh) return retop;
      Varnode *vn = retop->getIn(1);
      Datatype *ct = vn->getHigh()->getType();
      if (bestdt == (Datatype *)0) {
	res = retop;
	bestdt = ct;
      }
      else if (ct->typeOrder(*bestdt) < 0) {
	res = retop;
	bestdt = ct;
      }
    }
  }
  return res;
}

/// \brief Create new PcodeOp with 2 or 3 given operands
///
/// The new op will have a \e unique space output Varnode and will be inserted before
/// the given \e follow op.
/// \param follow is the \e follow up to insert the new PcodeOp before
/// \param opc is the op-code of the new PcodeOp
/// \param in1 is the first operand
/// \param in2 is the second operand
/// \param in3 is the optional third param
/// \return the new PcodeOp
PcodeOp *Funcdata::newOpBefore(PcodeOp *follow,OpCode opc,Varnode *in1,Varnode *in2,Varnode *in3)

{
  PcodeOp *newop;
  int4 size;

  size = (in3 == (Varnode *)0) ? 2 : 3;
  newop = newOp(size,follow->getAddr());
  opSetOpcode(newop,opc);
  newUniqueOut(in1->getSize(),newop);
  opSetInput(newop,in1,0);
  opSetInput(newop,in2,1);
  if (size==3)
    opSetInput(newop,in3,2);
  opInsertBefore(newop,follow);
  return newop;
}

/// \brief Create a new CPUI_INDIRECT around a PcodeOp with an indirect effect
///
/// Typically this is used to annotate data-flow, for the given storage range, passing
/// through a CALL or STORE. An output Varnode is automatically created.
/// \param indeffect is the PcodeOp with the indirect effect
/// \param addr is the starting address of the storage range to protect
/// \param size is the number of bytes in the storage range
/// \return the new CPUI_INDIRECT op
PcodeOp *Funcdata::newIndirectOp(PcodeOp *indeffect,const Address &addr,int4 size)

{
  Varnode *newin;
  PcodeOp *newop;

  newin = newVarnode(size,addr);
  newop = newOp(2,indeffect->getAddr());
  newVarnodeOut(size,addr,newop);
  opSetOpcode(newop,CPUI_INDIRECT);
  opSetInput(newop,newin,0);
  opSetInput(newop,newVarnodeIop(indeffect),1);
  opInsertBefore(newop,indeffect);
  return newop;
}

/// \brief Turn given PcodeOp into a CPUI_INDIRECT that \e indirectly \e creates a Varnode
///
/// An \e indirectly \e created Varnode effectively has no data-flow before the INDIRECT op
/// that defines it, and the value contained by the Varnode is not explicitly calculable.
/// \param op is the given PcodeOp to convert to a CPUI_INDIRECT
/// \param indeffect is the p-code causing the indirect effect
/// \param outvn is the (preexisting) Varnode that will be marked as \e created by the INDIRECT
/// \param possibleout is \b true if the output should be treated as a \e directwrite.
void Funcdata::setIndirectCreation(PcodeOp *op,PcodeOp *indeffect,Varnode *outvn,bool possibleout)

{
  Varnode *newin;

  newin = newConstant(outvn->getSize(),0);
  op->flags |= PcodeOp::indirect_creation;
  opSetOutput(op,outvn);
  if (!possibleout)
    newin->flags |= Varnode::indirect_creation;
  outvn->flags |= Varnode::indirect_creation;
  opSetOpcode(op,CPUI_INDIRECT);
  opSetInput(op,newin,0);
  opSetInput(op,newVarnodeIop(indeffect),1);
  opInsertBefore(op,indeffect);
}

/// \brief Build a CPUI_INDIRECT op that \e indirectly \e creates a Varnode
///
/// An \e indirectly \e created Varnode effectively has no data-flow before the INDIRECT op
/// that defines it, and the value contained by the Varnode is not explicitly calculable.
/// The new Varnode is allocated with a given storage range.
/// \param indeffect is the p-code causing the indirect effect
/// \param addr is the starting address of the given storage range
/// \param size is the number of bytes in the storage range
/// \param possibleout is \b true if the output should be treated as a \e directwrite.
/// \return the new CPUI_INDIRECT op
PcodeOp *Funcdata::newIndirectCreation(PcodeOp *indeffect,const Address &addr,int4 size,bool possibleout)

{
  Varnode *newout,*newin;
  PcodeOp *newop;

  newin = newConstant(size,0);
  newop = newOp(2,indeffect->getAddr());
  newop->flags |= PcodeOp::indirect_creation;
  newout = newVarnodeOut(size,addr,newop);
  if (!possibleout)
    newin->flags |= Varnode::indirect_creation;
  newout->flags |= Varnode::indirect_creation;
  opSetOpcode(newop,CPUI_INDIRECT);
  opSetInput(newop,newin,0);
  opSetInput(newop,newVarnodeIop(indeffect),1);
  opInsertBefore(newop,indeffect);
  return newop;
}

/// Data-flow through the given CPUI_INDIRECT op is truncated causing the output Varnode
/// to be \e indirectly \e created.
/// An \e indirectly \e created Varnode effectively has no data-flow before the INDIRECT op
/// that defines it, and the value contained by the Varnode is not explicitly calculable.
/// \param indop is the given CPUI_INDIRECT op
void Funcdata::truncateIndirect(PcodeOp *indop)

{
  Varnode *outvn = indop->getOut();
  Varnode *newin = newConstant(outvn->getSize(),0);

  indop->flags |= PcodeOp::indirect_creation;
  newin->flags |= Varnode::indirect_creation;
  outvn->flags |= Varnode::indirect_creation;

  opSetInput(indop,newin,0);
}

/// \brief Generate raw p-code for the function
///
/// Follow flow from the entry point generating PcodeOps for each instruction encountered.
/// The caller can provide a bounding range that constrains where control can flow to
/// and can also provide a maximum number of instructions that will be followed.
/// \param baddr is the beginning of the constraining range
/// \param eaddr is the end of the constraining range
/// \param insn_max is the maximum number of instructions to follow
void Funcdata::followFlow(const Address &baddr,const Address &eaddr,uint4 insn_max)

{
  if (!obank.empty()) {
    if ((flags & blocks_generated)==0)
      throw LowlevelError("Function loaded for inlining");
    return;	// Already translated
  }

  uint4 fl = 0;
  fl |= glb->flowoptions;	// Global flow options
  FlowInfo flow(*this,obank,bblocks,qlst);
  flow.setRange(baddr,eaddr);
  flow.setFlags(fl);
  if (insn_max != 0)
    flow.setMaximumInstructions(insn_max);
  flow.generateOps();
  size = flow.getSize();
  // Cannot keep track of function sizes in general because of non-contiguous functions
  //  glb->symboltab->update_size(name,size);

  flow.generateBlocks();
  flags |= blocks_generated;
  switchOverJumpTables(flow);
  if (flow.hasUnimplemented())
    flags |= unimplemented_present;
  if (flow.hasBadData())
    flags |= baddata_present;
}

/// \brief Generate a clone with truncated control-flow given a partial function
///
/// Existing p-code is cloned from another function whose flow has not been completely
/// followed. Artificial halt operators are inserted wherever flow is incomplete and
/// basic blocks are generated.
/// \param fd is the partial function to clone
/// \param flow is partial function's flow information
void Funcdata::truncatedFlow(const Funcdata *fd,const FlowInfo *flow)

{
  if (!obank.empty())
    throw LowlevelError("Trying to do truncated flow on pre-existing pcode");

  std::list<PcodeOp *>::const_iterator oiter; // Clone the raw pcode
  for(oiter=fd->obank.beginDead();oiter!=fd->obank.endDead();++oiter)
    cloneOp(*oiter,(*oiter)->getSeqNum());
  obank.setUniqId(fd->obank.getUniqId());

  // Clone callspecs
  for(int4 i=0;i<fd->qlst.size();++i) {
    FuncCallSpecs *oldspec = fd->qlst[i];
    PcodeOp *newop = findOp(oldspec->getOp()->getSeqNum());
    FuncCallSpecs *newspec = oldspec->clone(newop);
    Varnode *invn0 = newop->getIn(0);
    if (invn0->getSpace()->getType() == IPTR_FSPEC) { // Replace embedded pointer to callspec
      Varnode *newvn0 = newVarnodeCallSpecs(newspec);
      opSetInput(newop,newvn0,0);
      deleteVarnode(invn0);
    }
    qlst.push_back(newspec);
  }

  std::vector<JumpTable *>::const_iterator jiter; // Clone the jumptables
  for(jiter=fd->jumpvec.begin();jiter!=fd->jumpvec.end();++jiter) {
    PcodeOp *indop = (*jiter)->getIndirectOp();
    if (indop == (PcodeOp *)0)	// If indirect op has not been linked, this is probably a jumptable override
      continue;			// that has not been reached by the flow yet, so we ignore/truncate it
    PcodeOp *newop = findOp(indop->getSeqNum());
    if (newop == (PcodeOp *)0)
      throw LowlevelError("Could not trace jumptable across partial clone");
    JumpTable *jtclone = new JumpTable(*jiter);
    jtclone->setIndirectOp(newop);
    jumpvec.push_back(jtclone);
  }

  FlowInfo partialflow(*this,obank,bblocks,qlst,flow); // Clone the flow
  if (partialflow.hasInject())
    partialflow.injectPcode();
  // Clear error reporting flags
  // Keep possible unreachable flag
  partialflow.clearFlags(~((uint4)FlowInfo::possible_unreachable));

  partialflow.generateBlocks(); // Generate basic blocks for partial flow
  flags |= blocks_generated;
}

/// \brief In-line the p-code from another function into \b this function
///
/// Raw PcodeOps for the in-line function are generated and then cloned into
/// \b this function.  Depending on the control-flow complexity of the in-line
/// function, the PcodeOps are injected as if they are all part of the call site
/// address (EZModel), or the PcodeOps preserve their address and extra branch
/// instructions are inserted to integrate control-flow of the in-line into
/// the calling function.
/// \param inlinefd is the function to in-line
/// \param flow is the flow object being injected
/// \param callop is the site of the injection
/// \return \b true if the injection was successful
bool Funcdata::inlineFlow(Funcdata *inlinefd,FlowInfo &flow,PcodeOp *callop)

{
  inlinefd->getArch()->clearAnalysis(inlinefd);
  FlowInfo inlineflow(*inlinefd,inlinefd->obank,inlinefd->bblocks,inlinefd->qlst);
  inlinefd->obank.setUniqId( obank.getUniqId() );

  // Generate the pcode ops to be inlined
  Address baddr(baseaddr.getSpace(),0);
  Address eaddr(baseaddr.getSpace(),~((uintb)0));
  inlineflow.setRange(baddr,eaddr);
  inlineflow.setFlags(FlowInfo::error_outofbounds|FlowInfo::error_unimplemented|
		      FlowInfo::error_reinterpreted|FlowInfo::flow_forinline);
  inlineflow.forwardRecursion(flow);
  inlineflow.generateOps();

  if (inlineflow.checkEZModel()) {
    // With an EZ clone there are no jumptables to clone
    std::list<PcodeOp *>::const_iterator oiter = obank.endDead();
    --oiter;			// There is at least one op
    flow.inlineEZClone(inlineflow,callop->getAddr());
    ++oiter;
    if (oiter != obank.endDead()) { // If there was at least one PcodeOp cloned
      PcodeOp *firstop = *oiter;
      oiter = obank.endDead();
      --oiter;
      PcodeOp *lastop = *oiter;
      obank.moveSequenceDead(firstop,lastop,callop); // Move cloned sequence to right after callop
      if (callop->isBlockStart())
	firstop->setFlag(PcodeOp::startbasic); // First op of inline inherits callop's startbasic flag
      else
	firstop->clearFlag(PcodeOp::startbasic);
    }
    opDestroyRaw(callop);
  }
  else {
    Address retaddr;
    if (!flow.testHardInlineRestrictions(inlinefd,callop,retaddr))
      return false;
    std::vector<JumpTable *>::const_iterator jiter; // Clone any jumptables from inline piece
    for(jiter=inlinefd->jumpvec.begin();jiter!=inlinefd->jumpvec.end();++jiter) {
      JumpTable *jtclone = new JumpTable(*jiter);
      jumpvec.push_back(jtclone);
    }
    flow.inlineClone(inlineflow,retaddr);

    // Convert CALL op to a jump
    while(callop->numInput()>1)
      opRemoveInput(callop,callop->numInput()-1);

    opSetOpcode(callop,CPUI_BRANCH);
    Varnode *inlineaddr = newCodeRef( inlinefd->getAddress() );
    opSetInput(callop,inlineaddr,0);
  }

  obank.setUniqId( inlinefd->obank.getUniqId() );
  
  return true;
}

/// \brief Find the primary branch operation for an instruction
///
/// For machine instructions that branch, this finds the \e primary PcodeOp that performs
/// the branch.  The instruction is provided as a std::list of p-code ops, and the caller can
/// specify whether they expect to see a \e branch, \e call, or \e return operation.
/// \param iter is the start of the operations for the instruction
/// \param enditer is the end of the operations for the instruction
/// \param findbranch is \b true if the caller expects to see a BRANCH, CBRANCH, or BRANCHIND
/// \param findcall is \b true if the caller expects to see CALL or CALLIND
/// \param findreturn is \b true if the caller expects to see RETURN
/// \return the first branching PcodeOp that matches the criteria or NULL
PcodeOp *Funcdata::findPrimaryBranch(PcodeOpTree::const_iterator iter,PcodeOpTree::const_iterator enditer,
				     bool findbranch,bool findcall,bool findreturn)
{
  while(iter != enditer) {
    PcodeOp *op = (*iter).second;
    switch(op->code()) {
    case CPUI_BRANCH:
    case CPUI_CBRANCH:
      if (findbranch) {
	if (!op->getIn(0)->isConstant()) // Make sure this is not an internal branch
	  return op;
      }
      break;
    case CPUI_BRANCHIND:
      if (findbranch)
	return op;
      break;
    case CPUI_CALL:
    case CPUI_CALLIND:
      if (findcall)
	return op;
      break;
    case CPUI_RETURN:
      if (findreturn)
	return op;
      break;
    default:
      break;
    }
    ++iter;
  }
  return (PcodeOp *)0;
}

/// \brief Override the control-flow p-code for a particular instruction
///
/// P-code in \b this function is modified to change the control-flow of
/// the instruction at the given address, based on the Override type.
/// \param addr is the given address of the instruction to modify
/// \param type is the Override type
void Funcdata::overrideFlow(const Address &addr,uint4 type)

{
  PcodeOpTree::const_iterator iter = beginOp(addr);
  PcodeOpTree::const_iterator enditer = endOp(addr);

  PcodeOp *op = (PcodeOp *)0;
  if (type == Override::BRANCH)
    op = findPrimaryBranch(iter,enditer,false,true,true);
  else if (type == Override::CALL)
    op = findPrimaryBranch(iter,enditer,true,false,true);
  else if (type == Override::CALL_RETURN)
    op = findPrimaryBranch(iter,enditer,true,false,true);
  else if (type == Override::RETURN)
    op = findPrimaryBranch(iter,enditer,true,true,false);

  if ((op == (PcodeOp *)0)||(!op->isDead()))
    throw LowlevelError("Could not apply flowoverride");

  OpCode opc = op->code();
  if (type == Override::BRANCH) {
    if (opc == CPUI_CALL)
      opSetOpcode(op,CPUI_BRANCH);
    else if (opc == CPUI_CALLIND)
      opSetOpcode(op,CPUI_BRANCHIND);
    else if (opc == CPUI_RETURN)
      opSetOpcode(op,CPUI_BRANCHIND);
  }
  else if ((type == Override::CALL)||(type == Override::CALL_RETURN)) {
    if (opc == CPUI_BRANCH)
      opSetOpcode(op,CPUI_CALL);
    else if (opc == CPUI_BRANCHIND)
      opSetOpcode(op,CPUI_CALLIND);
    else if (opc == CPUI_CBRANCH)
      throw LowlevelError("Do not currently support CBRANCH overrides");
    else if (opc == CPUI_RETURN)
      opSetOpcode(op,CPUI_CALLIND);
    if (type == Override::CALL_RETURN) { // Insert a new return op after call
      PcodeOp *newReturn = newOp(1,addr);
      opSetOpcode(newReturn,CPUI_RETURN);
      opSetInput(newReturn,newConstant(1,0),0);
      opDeadInsertAfter(newReturn,op);
    }
  }
  else if (type == Override::RETURN) {
    if ((opc == CPUI_BRANCH)||(opc == CPUI_CBRANCH)||(opc == CPUI_CALL))
      throw LowlevelError("Do not currently support complex overrides");
    else if (opc == CPUI_BRANCHIND)
      opSetOpcode(op,CPUI_RETURN);
    else if (opc == CPUI_CALLIND)
      opSetOpcode(op,CPUI_RETURN);
  }
}

/// Do in-place replacement of
///   - `#c <= x`   with  `#c-1 < x`   OR
///   - `x <= #c`   with  `x < #c+1`
///
/// \param data is the function being analyzed
/// \param op is comparison PcodeOp
/// \return true if a valid replacement was performed
bool Funcdata::replaceLessequal(Funcdata &data,PcodeOp *op)

{
  Varnode *vn;
  int4 i;
  intb val,diff;
  
  if ((vn=op->getIn(0))->isConstant()) {
    diff = -1;
    i = 0;
  }
  else if ((vn=op->getIn(1))->isConstant()) {
    diff = 1;
    i = 1;
  }
  else
    return false;

  val = vn->getOffset();	// Treat this as signed value
  sign_extend(val,8*vn->getSize()-1);
  if (op->code() == CPUI_INT_SLESSEQUAL) {
    if ((val<0)&&(val+diff>0)) return false; // Check for sign overflow
    if ((val>0)&&(val+diff<0)) return false;
    data.opSetOpcode(op,CPUI_INT_SLESS);
  }
  else {			// Check for unsigned overflow
    if ((diff==-1)&&(val==0)) return false;
    if ((diff==1)&&(val==-1)) return false;
    data.opSetOpcode(op,CPUI_INT_LESS);
  }
  uintb res = (val+diff) & calc_mask(vn->getSize());
  Varnode *newvn = data.newConstant(vn->getSize(),res);
  newvn->copySymbol(vn);	// Preserve data-type (and any Symbol info)
  data.opSetInput(op,newvn,i);
  return true;
}

/// \brief Trace a boolean value to a std::set of PcodeOps that can be changed to flip the boolean value
///
/// The boolean Varnode is either the output of the given PcodeOp or the
/// first input if the PcodeOp is a CBRANCH. The std::list of ops that need flipping is
/// returned in an array
/// \param op is the given PcodeOp
/// \param fliplist is the array that will hold the ops to flip
/// \return 0 if the change normalizes, 1 if the change is ambivalent, 2 if the change does not normalize
int4 opFlipInPlaceTest(PcodeOp *op,std::vector<PcodeOp *> &fliplist)

{
  Varnode *vn;
  int4 subtest1,subtest2;
  switch(op->code()) {
  case CPUI_CBRANCH:
    vn = op->getIn(1);
    if (vn->loneDescend() != op) return 2;
    if (!vn->isWritten()) return 2;
    return opFlipInPlaceTest(vn->getDef(),fliplist);
  case CPUI_INT_EQUAL:
  case CPUI_FLOAT_EQUAL:
    fliplist.push_back(op);
    return 1;
  case CPUI_BOOL_NEGATE:
  case CPUI_INT_NOTEQUAL:
  case CPUI_FLOAT_NOTEQUAL:
    fliplist.push_back(op);
    return 0;
  case CPUI_INT_SLESS:
  case CPUI_INT_LESS:
    vn = op->getIn(0);
    fliplist.push_back(op);
    if (!vn->isConstant()) return 1;
    return 0;
  case CPUI_INT_SLESSEQUAL:
  case CPUI_INT_LESSEQUAL:
    vn = op->getIn(1);
    fliplist.push_back(op);
    if (vn->isConstant()) return 1;
    return 0;
  case CPUI_BOOL_OR:
  case CPUI_BOOL_AND:
    vn = op->getIn(0);
    if (vn->loneDescend() != op) return 2;
    if (!vn->isWritten()) return 2;
    subtest1 = opFlipInPlaceTest(vn->getDef(),fliplist);
    if (subtest1 == 2)
      return 2;
    vn = op->getIn(1);
    if (vn->loneDescend() != op) return 2;
    if (!vn->isWritten()) return 2;
    subtest2 = opFlipInPlaceTest(vn->getDef(),fliplist);
    if (subtest2 == 2)
      return 2;
    fliplist.push_back(op);
    return subtest1;		// Front of AND/OR must be normalizing
  default:
    break;
  }
  return 2;
}

/// \brief Perform op-code flips (in-place) to change a boolean value
///
/// The precomputed std::list of PcodeOps have their op-codes modified to
/// facilitate the flip.
/// \param data is the function being modified
/// \param fliplist is the std::list of PcodeOps to modify
void opFlipInPlaceExecute(Funcdata &data,std::vector<PcodeOp *> &fliplist)

{
  Varnode *vn;
  for(int4 i=0;i<fliplist.size();++i) {
    PcodeOp *op = fliplist[i];
    bool flipyes;
    OpCode opc = get_booleanflip(op->code(),flipyes);
    if (opc == CPUI_COPY) {	// We remove this (CPUI_BOOL_NEGATE) entirely
      vn = op->getIn(0);
      PcodeOp *otherop = op->getOut()->loneDescend(); // Must be a lone descendant
      int4 slot = otherop->getSlot(op->getOut());
      data.opSetInput(otherop,vn,slot);	// Propagate -vn- into otherop
      data.opDestroy(op);
    }
    else if (opc == CPUI_MAX) {
      if (op->code() == CPUI_BOOL_AND)
	data.opSetOpcode(op,CPUI_BOOL_OR);
      else if (op->code() == CPUI_BOOL_OR)
	data.opSetOpcode(op,CPUI_BOOL_AND);
      else
	throw LowlevelError("Bad flipInPlace op");
    }
    else {
      data.opSetOpcode(op,opc);
      if (flipyes) {
	data.opSwapInput(op,0,1);

	if ((opc == CPUI_INT_LESSEQUAL)||(opc == CPUI_INT_SLESSEQUAL))
	  Funcdata::replaceLessequal(data,op);
      }
    }
  }
}

/// \brief Get the earliest use/read of a Varnode in a specified basic block
///
/// \param vn is the Varnode to search for
/// \param bl is the specified basic block in which to search
/// \return the earliest PcodeOp reading the Varnode or NULL
PcodeOp *earliestUseInBlock(Varnode *vn,BlockBasic *bl)

{
  std::list<PcodeOp *>::const_iterator iter;
  PcodeOp *res = (PcodeOp *)0;

  for(iter=vn->beginDescend();iter!=vn->endDescend();++iter) {
    PcodeOp *op = *iter;
    if (op->getParent() != bl) continue;
    if (res == (PcodeOp *)0)
      res = op;
    else {
      if (op->getSeqNum().getOrder() < res->getSeqNum().getOrder())
	res = op;
    }
  }
  return res;
}

/// \brief Find a duplicate calculation of a given PcodeOp reading a specific Varnode
///
/// We only match 1 level of calculation.  Additionally the duplicate must occur in the
/// indicated basic block, earlier than a specified op.
/// \param op is the given PcodeOp
/// \param vn is the specific Varnode that must be involved in the calculation
/// \param bl is the indicated basic block
/// \param earliest is the specified op to be earlier than
/// \return the discovered duplicate PcodeOp or NULL
PcodeOp *cseFindInBlock(PcodeOp *op,Varnode *vn,BlockBasic *bl,PcodeOp *earliest)

{
  std::list<PcodeOp *>::const_iterator iter;
  
  for(iter=vn->beginDescend();iter!=vn->endDescend();++iter) {
    PcodeOp *res = *iter;
    if (res == op) continue;	// Must not be -op-
    if (res->getParent() != bl) continue; // Must be in -bl-
    if (earliest != (PcodeOp *)0) {
      if (earliest->getSeqNum().getOrder() < res->getSeqNum().getOrder()) continue; // Must occur earlier than earliest
    }
    Varnode *outvn1 = op->getOut();
    Varnode *outvn2 = res->getOut();
    if (outvn2 == (Varnode *)0) continue;
    Varnode *buf1[2];
    Varnode *buf2[2];
    if (functionalEqualityLevel(outvn1,outvn2,buf1,buf2) == 0)
      return res;
  }
  return (PcodeOp *)0;
}

/// \brief Perform a Common Subexpression Elimination step
///
/// Assuming the two given PcodeOps perform the identical operation on identical operands
/// (depth 1 functional equivalence) eliminate the redundancy.  Return the remaining (dominating)
/// PcodeOp. If neither op dominates the other, both are eliminated, and a new PcodeOp
/// is built at a commonly accessible point.
/// \param data is the function being modified
/// \param op1 is the first of the given PcodeOps
/// \param op2 is the second given PcodeOp
/// \return the dominating PcodeOp
PcodeOp *cseElimination(Funcdata &data,PcodeOp *op1,PcodeOp *op2)

{
  PcodeOp *replace;

  if (op1->getParent() == op2->getParent()) {
    if (op1->getSeqNum().getOrder() < op2->getSeqNum().getOrder())
      replace = op1;
    else
      replace = op2;
  }
  else {
    BlockBasic *common;
    common = (BlockBasic *)FlowBlock::findCommonBlock(op1->getParent(),op2->getParent());
    if (common == op1->getParent())
      replace = op1;
    else if (common == op2->getParent())
      replace = op2;
    else {			// Neither op is ancestor of the other
      replace = data.newOp(op1->numInput(),common->getStop());
      data.opSetOpcode(replace,op1->code());
      data.newVarnodeOut(op1->getOut()->getSize(),op1->getOut()->getAddr(),replace);
      for(int4 i=0;i<op1->numInput();++i) {
	if (op1->getIn(i)->isConstant())
	  data.opSetInput(replace,data.newConstant(op1->getIn(i)->getSize(),op1->getIn(i)->getOffset()),i);
	else
	  data.opSetInput(replace,op1->getIn(i),i);
      }
      data.opInsertEnd(replace,common);
    }
  }
  if (replace != op1) {
    data.totalReplace(op1->getOut(),replace->getOut());
    data.opDestroy(op1);
  }
  if (replace != op2) {
    data.totalReplace(op2->getOut(),replace->getOut());
    data.opDestroy(op2);
  }
  return replace;
}

/// \brief Comparator for (hash,PcodeOp) pairs
///
/// Compare by hash.
/// \param a is the first std::pair
/// \param b is the second std::pair
/// \return \b true if the first comes before the second
static bool compareCseHash(const std::pair<uintm,PcodeOp *> &a,const std::pair<uintm,PcodeOp *> &b)

{
  return (a.first < b.first);
}

/// \brief Perform Common Subexpression Elimination on a std::list of Varnode descendants
///
/// The std::list consists of PcodeOp descendants of a single Varnode paired with a hash value.
/// The hash serves as a primary test for duplicate calculations; if it doesn't match
/// the PcodeOps aren't common subexpressions.  This method searches for hash matches
/// then does secondary testing and eliminates any redundancy it finds.
/// \param data is the function being modified
/// \param std::list is the std::list of (hash, PcodeOp) pairs
/// \param outlist will hold Varnodes produced by duplicate calculations
void cseEliminateList(Funcdata &data,std::vector< std::pair<uintm,PcodeOp *> > &list,std::vector<Varnode *> &outlist)

{
  PcodeOp *op1,*op2,*resop;
  std::vector< std::pair<uintm,PcodeOp *> >::iterator liter1,liter2;

  if (list.empty()) return;
  stable_sort(list.begin(),list.end(),compareCseHash);
  liter1 = list.begin();
  liter2 = list.begin();
  liter2++;
  while(liter2 != list.end()) {
    if ((*liter1).first == (*liter2).first) {
      op1 = (*liter1).second;
      op2 = (*liter2).second;
      if ((!op1->isDead())&&(!op2->isDead())&&op1->isCseMatch(op2)) {
	Varnode *outvn1 = op1->getOut();
	Varnode *outvn2 = op2->getOut();
	if ((outvn1 == (Varnode *)0)||data.isHeritaged(outvn1)) {
	  if ((outvn2 == (Varnode *)0)||data.isHeritaged(outvn2)) {
	    resop = cseElimination(data,op1,op2);
	    outlist.push_back(resop->getOut());
	  }
	}
      }
    }
    liter1++;
    liter2++;
  }
}
}
