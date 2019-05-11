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
#ifndef __CPUI_XML__
#define __CPUI_XML__

#include "types.h"
#include <fstream>
#include <iomanip>
#include <string>
#include <vector>
#include <map>

namespace GhidraDec {

class Attributes {
  std::string *elementname;
  std::string bogus_uri;
  std::string prefix;
  std::vector<std::string *> name;
  std::vector<std::string *> value;
public:
  Attributes(std::string *el) { elementname = el; }
  ~Attributes(void) { 
    for(uint4 i=0;i<name.size();++i) { delete name[i]; delete value[i]; }
    delete elementname;
  }
  const std::string &getelemURI(void) const { return bogus_uri; }
  const std::string &getelemName(void) const { return *elementname; }
  void add_attribute(std::string *nm,std::string *vl) { name.push_back(nm); value.push_back(vl); }
				// The official SAX interface
  int4 getLength(void) const { return name.size(); }
  const std::string &getURI(int4 index) const { return bogus_uri; }
  const std::string &getLocalName(int4 index) const { return *name[index]; }
  const std::string &getQName(int4 index) const { return *name[index]; }
  //  int4 getIndex(const std::string &uri,const std::string &localName) const;
  //  int4 getIndex(const std::string &qualifiedName) const;
  //  const std::string &getType(int4 index) const;
  //  const std::string &getType(const std::string &uri,const std::string &localName) const;
  //  const std::string &getType(const std::string &qualifiedName) const;
  const std::string &getValue(int4 index) const { return *value[index]; }
  //const std::string &getValue(const std::string &uri,const std::string &localName) const;
  const std::string &getValue(const std::string &qualifiedName) const {
    for(uint4 i=0;i<name.size();++i)
      if (*name[i] == qualifiedName) return *value[i];
    return bogus_uri;
  }
};

typedef void *Locator;

class ContentHandler {
public:
  virtual ~ContentHandler(void) {}
  virtual void setDocumentLocator(Locator locator)=0;
  virtual void startDocument(void)=0;
  virtual void endDocument(void)=0;
  virtual void startPrefixMapping(const std::string &prefix,const std::string &uri)=0;
  virtual void endPrefixMapping(const std::string &prefix)=0;
  virtual void startElement(const std::string &namespaceURI,const std::string &localName,
			    const std::string &qualifiedName,const Attributes &atts)=0;
  virtual void endElement(const std::string &namespaceURI,const std::string &localName,
			  const std::string &qualifiedName)=0;
  virtual void characters(const char *text,int4 start,int4 length)=0;
  virtual void ignorableWhitespace(const char *text,int4 start,int4 length)=0;
  virtual void setVersion(const std::string &version)=0;
  virtual void setEncoding(const std::string &encoding)=0;
  virtual void processingInstruction(const std::string &target,const std::string &data)=0;
  virtual void skippedEntity(const std::string &name)=0;
  virtual void setError(const std::string &errmsg)=0;
};

class Element;
typedef std::vector<Element *> List;

class Element {
  std::string name;
  std::string content;
  std::vector<std::string> attr;
  std::vector<std::string> value;
protected:
  Element *parent;
  List children;
public:
  Element(Element *par) { parent = par; }
  ~Element(void);
  void setName(const std::string &nm) { name = nm; }
  void addContent(const char *str,int4 start,int4 length) { 
    //    for(int4 i=0;i<length;++i) content += str[start+i]; }
    content.append(str+start,length); }
  void addChild(Element *child) { children.push_back(child); }
  void addAttribute(const std::string &nm,const std::string &vl) {
    attr.push_back(nm); value.push_back(vl); }
  Element *getParent(void) const { return parent; }
  const std::string &getName(void) const { return name; }
  const List &getChildren(void) const { return children; }
  const std::string &getContent(void) const { return content; }
  const std::string &getAttributeValue(const std::string &nm) const;
  int4 getNumAttributes(void) const { return attr.size(); }
  const std::string &getAttributeName(int4 i) const { return attr[i]; }
  const std::string &getAttributeValue(int4 i) const { return value[i]; }
};

class Document : public Element {
public:
  Document(void) : Element((Element *)0) {}
  Element *getRoot(void) const { return *children.begin(); }
};

class TreeHandler : public ContentHandler {
  Element *root;
  Element *cur;
  std::string error;
public:
  TreeHandler(Element *rt) { root = rt; cur = root; }
  virtual ~TreeHandler(void) {}
  virtual void setDocumentLocator(Locator locator) {}
  virtual void startDocument(void) {}
  virtual void endDocument(void) {}
  virtual void startPrefixMapping(const std::string &prefix,const std::string &uri) {}
  virtual void endPrefixMapping(const std::string &prefix) {}
  virtual void startElement(const std::string &namespaceURI,const std::string &localName,
			    const std::string &qualifiedName,const Attributes &atts);
  virtual void endElement(const std::string &namespaceURI,const std::string &localName,
			  const std::string &qualifiedName);
  virtual void characters(const char *text,int4 start,int4 length);
  virtual void ignorableWhitespace(const char *text,int4 start,int4 length) {}
  virtual void processingInstruction(const std::string &target,const std::string &data) {}
  virtual void setVersion(const std::string &val) {}
  virtual void setEncoding(const std::string &val) {}
  virtual void skippedEntity(const std::string &name) {}
  virtual void setError(const std::string &errmsg) { error = errmsg; }
  const std::string &getError(void) const { return error; }
};

// Class for managing xml documents during initialization
class DocumentStorage {
  std::vector<Document *> doclist;
  std::map<std::string,const Element *> tagmap;
public:
  ~DocumentStorage(void);
  Document *parseDocument(std::istream &s);
  Document *openDocument(const std::string &filename);
  void registerTag(const Element *el);
  const Element *getTag(const std::string &nm) const;
};

struct XmlError {
  std::string explain;		// Explanatory std::string
  XmlError(const std::string &s) { explain = s; }
};

extern int4 xml_parse(std::istream &i,ContentHandler *hand,int4 dbg=0);
extern Document *xml_tree(std::istream &i);
extern void xml_escape(std::ostream &s,const char *str);

// Some helper functions for producing XML
inline void a_v(std::ostream &s,const std::string &attr,const std::string &val)

{
  s << ' ' << attr << "=\"";
  xml_escape(s,val.c_str());
  s << "\"";
}

inline void a_v_i(std::ostream &s,const std::string &attr,intb val)

{
  s << ' ' << attr << "=\"" << std::dec << val << "\"";
}

inline void a_v_u(std::ostream &s,const std::string &attr,uintb val)

{
  s << ' ' << attr << "=\"0x" << std::dec << val << "\"";
}

inline void a_v_b(std::ostream &s,const std::string &attr,bool val)

{
  s << ' ' << attr << "=\"";
  if (val)
    s << "true";
  else
    s << "false";
  s << "\"";
}

inline bool xml_readbool(const std::string &attr)

{
  if (attr.size()==0) return false;
  char firstc = attr[0];
  if (firstc=='t') return true;
  if (firstc=='1') return true;
  if (firstc=='y') return true;         // For backward compatibility
  return false;
}
}
#endif
