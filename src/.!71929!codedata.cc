/* ###
 * IP: GHIDRA
 * EXCLUDE: YES
 * NOTE: Target command uses BFD stuff which is GPL 3
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
#include "codedata.hh"
#include "loadimage_bfd.hh"

namespace GhidraDec {
// Constructing this registers the capability
IfaceCodeDataCapability IfaceCodeDataCapability::ifaceCodeDataCapability;

IfaceCodeDataCapability::IfaceCodeDataCapability(void)

{
  name = "codedata";
}

void IfaceCodeDataCapability::registerCommands(IfaceStatus *status)

{
  status->registerCom(new IfcCodeDataInit(),"codedata","init");
  status->registerCom(new IfcCodeDataTarget(),"codedata","target");
  status->registerCom(new IfcCodeDataRun(),"codedata","run");
  status->registerCom(new IfcCodeDataDumpModelHits(),"codedata","dump","hits");
  status->registerCom(new IfcCodeDataDumpCrossRefs(),"codedata","dump","crossrefs");
  status->registerCom(new IfcCodeDataDumpStarts(),"codedata","dump","starts");
  status->registerCom(new IfcCodeDataDumpUnlinked(),"codedata","dump","unlinked");
  status->registerCom(new IfcCodeDataDumpTargetHits(),"codedata","dump","targethits");
}

void DisassemblyEngine::init(const Translate *t)

{
  trans = t;
  jumpaddr.clear();
  targetoffsets.clear();
}

void DisassemblyEngine::dump(const Address &addr,OpCode opc,VarnodeData *outvar,VarnodeData *vars,int4 isize)

{
  lastop = opc;
  switch(opc) {
  case CPUI_CALL:
    hascall = true;
    // fallthru
  case CPUI_BRANCH:
  case CPUI_CBRANCH:
    jumpaddr.push_back(Address(vars[0].space,vars[0].offset));
    break;
  case CPUI_COPY:
  case CPUI_BRANCHIND:
  case CPUI_CALLIND:
    if (targetoffsets.end() != targetoffsets.find( vars[0].offset )) {
      hitsaddress = true;
      targethit = vars[0].offset;
    }
    break;
  case CPUI_LOAD:
    if (targetoffsets.end() != targetoffsets.find( vars[1].offset )) {
      hitsaddress = true;
      targethit = vars[1].offset;
    }
    break;
  default:
    break;
  }
}

void DisassemblyEngine::disassemble(const Address &addr,DisassemblyResult &res)

{
  jumpaddr.clear();
  lastop = CPUI_COPY;
  hascall = false;
  hitsaddress = false;
  res.flags = 0;
  try {
    res.length = trans->oneInstruction(*this,addr);
  } catch(BadDataError &err) {
    res.success = false;
    return;
  } catch(DataUnavailError &err) {
    res.success = false;
    return;
  } catch(UnimplError &err) {
    res.length = err.instruction_length;
  }
  res.success = true;
  if (hascall)
    res.flags |= CodeUnit::call;
  if (hitsaddress) {
    res.flags |= CodeUnit::targethit;
    res.targethit = targethit;
  }
  Address lastaddr = addr + res.length;
  switch(lastop) {
  case CPUI_BRANCH:
  case CPUI_BRANCHIND:
    if (hitsaddress)
      res.flags |= CodeUnit::thunkhit; // Hits target via indirect jump
    break;
  case CPUI_RETURN:
    break;
  default:
    res.flags |= CodeUnit::fallthru;
    break;
  }
  for(int4 i=0;i<jumpaddr.size();++i) {
    if (jumpaddr[i] == lastaddr)
      res.flags |= CodeUnit::fallthru;
    else if (jumpaddr[i] != addr) {
      res.flags |= CodeUnit::jump;
      res.jumpaddress = jumpaddr[i];
    }
  }
}

void CodeDataAnalysis::init(Architecture *g)

{
  glb = g;
  disengine.init(glb->translate);
  alignment = glb->translate->getAlignment();
  modelhits.clear();
  codeunit.clear();
  fromto_crossref.clear();
  tofrom_crossref.clear();
  taintlist.clear();
  unlinkedstarts.clear();
  targethits.clear();
  targets.clear();
}

void CodeDataAnalysis::pushTaintAddress(const Address &addr)

{
  std::map<Address,CodeUnit>::iterator iter;

  iter = codeunit.upper_bound(addr); // First after
  if (iter 
