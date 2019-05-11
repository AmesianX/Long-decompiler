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
#include "raw_arch.hh"

namespace GhidraDec {
// Constructing this object registers the capability
RawBinaryArchitectureCapability RawBinaryArchitectureCapability::rawBinaryArchitectureCapability;

RawBinaryArchitectureCapability::RawBinaryArchitectureCapability(void)

{
  name = "raw";
}

RawBinaryArchitectureCapability::~RawBinaryArchitectureCapability(void)

{
  SleighArchitecture::shutdown();
}

Architecture *RawBinaryArchitectureCapability::buildArchitecture(const std::string &filename,const std::string &target,std::ostream *estream)

{
  return new RawBinaryArchitecture(filename,target,estream);
}

bool RawBinaryArchitectureCapability::isFileMatch(const std::string &filename) const

{
  return true;			// File can always be opened as raw binary
}

bool RawBinaryArchitectureCapability::isXmlMatch(Document *doc) const

{
  return (doc->getRoot()->getName() == "raw_savefile");
}

void RawBinaryArchitecture::buildLoader(DocumentStorage &store)

{
  RawLoadImage *ldr;

  collectSpecFiles(*errorstream);
  ldr = new RawLoadImage(getFilename());
  ldr->open();
  if (adjustvma != 0)
    ldr->adjustVma(adjustvma);
  loader = ldr;
}

void RawBinaryArchitecture::resolveArchitecture(void)

{
  archid = getTarget();	// Nothing to derive from the image itself, we just copy in the passed in target
  SleighArchitecture::resolveArchitecture();
}

void RawBinaryArchitecture::postSpecFile(void)

{
  ((RawLoadImage *)loader)->attachToSpace(getDefaultSpace());	 // Attach default space to loader
}

RawBinaryArchitecture::RawBinaryArchitecture(const std::string &fname,const std::string &targ,std::ostream *estream)
  : SleighArchitecture(fname,targ,estream)
{
  adjustvma = 0;
}

void RawBinaryArchitecture::saveXml(std::ostream &s) const

{
  s << "<raw_savefile";
  saveXmlHeader(s);
  a_v_u(s,"adjustvma",adjustvma);
  s << ">\n";
  types->saveXmlCoreTypes(s);
  SleighArchitecture::saveXml(s);
  s << "</raw_savefile>\n";
}

void RawBinaryArchitecture::restoreXml(DocumentStorage &store)

{
  const Element *el = store.getTag("raw_savefile");
  if (el == (const Element *)0)
    throw LowlevelError("Could not find raw_savefile tag");

  restoreXmlHeader(el);
  {
    std::istringstream s( el->getAttributeValue("adjustvma"));
    s.unsetf(std::ios::dec | std::ios::dec | std::ios::oct);
    s >> adjustvma;
  }
  const List &std::list(el->getChildren());
  List::const_iterator iter;

  iter = std::list.begin();
  if (iter != std::list.end()) {
    if ((*iter)->getName() == "coretypes") {
      store.registerTag(*iter);
      ++iter;
    }
  }
  init(store);			// Load the image and configure

  if (iter != std::list.end()) {
    store.registerTag(*iter);
    SleighArchitecture::restoreXml(store);
  }
}
}
