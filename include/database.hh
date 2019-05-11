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
/// \file database.hh
/// \brief Symbol and Scope objects for the decompiler
///
/// These implement the main symbol table, with support for symbols, local and global
/// scopes, namespaces etc.  Search can be by name or the address of the Symbol storage
/// location.

#ifndef __CPUI_DATABASE__
#define __CPUI_DATABASE__

#include "variable.hh"
#include "partmap.hh"
#include "rangemap.hh"

namespace GhidraDec {
class Architecture;
class Funcdata;
class Scope;
class Database;
class Symbol;
class PrintLanguage;

/// \brief A storage location for a particular Symbol
///
/// Where a Symbol is stored, as a byte address and a size, is of particular importance
/// to the decompiler. This class encapsulates this storage meta-data. A single Symbol split
/// across multiple storage locations is supported by the \b offset and \b size fields. The
/// \b hash field supports \e dynamic storage, where a Symbol is represented by a constant
/// or a temporary register. In this case, storage must be tied to the particular p-code
/// operators using the value.
///
/// A particular memory address does \b not have to represent the symbol across all code. Storage
/// may get recycled for different Symbols at different points in the code. The \b uselimit object
/// defines the range of instruction addresses over which a particular memory address does
/// represent a Symbol, with the convention that an empty \b uselimit indicates the storage
/// holds the Symbol across \e all code.
class SymbolEntry {
  friend class Scope;
  Symbol *symbol;		///< Symbol object being mapped
  uint4 extraflags;		///< Varnode flags specific to this storage location
  Address addr;			///< Starting address of the storage location
  uint8 hash;			///< A dynamic storage address (an alternative to \b addr for dynamic symbols)
  int4 offset;			///< Offset into the Symbol that \b this covers
  int4 size;			///< Number of bytes consumed by \b this (piece of the) storage
  RangeList uselimit;		///< Code address ranges where this storage is valid
  SymbolEntry(Symbol *sym);	///< Construct a mapping for a Symbol without an address
public:
  /// \brief Initialization data for a SymbolEntry to facilitate a rangemap
  ///
  /// This is all the raw pieces of a SymbolEntry for a (non-dynamic) Symbol except
  /// the offset of the main address and the size, which are provided by the
  /// (rangemap compatible) SymbolEntry constructor.
  class EntryInitData {
    friend class SymbolEntry;
    AddrSpace *space;		///< The address space of the main SymbolEntry starting address
    Symbol *symbol;		///< The symbol being mapped
    uint4 extraflags;		///< Varnode flags specific to the storage location
    int4 offset;		///< Starting offset of the portion of the Symbol being covered
    const RangeList &uselimit;	///< Reference to the range of code addresses for which the storage is valid
  public:
    EntryInitData(Symbol *sym,uint4 exfl,AddrSpace *spc,int4 off,const RangeList &ul)
      : uselimit(ul) { symbol = sym; extraflags=exfl; space = spc; offset = off; }	///< Constructor
  };

  /// \brief Class for sub-sorting different SymbolEntry objects at the same address
  ///
  /// This is built from the SymbolEntry \b uselimit object (see SymbolEntry::getSubsort())
  /// Relevant portions of an Address object or pulled out for smaller storage and quick comparisons.
  class EntrySubsort {
    friend class SymbolEntry;
    int4 useindex;			///< Index of the sub-sorting address space
    uintb useoffset;			///< Offset into the sub-sorting address space
  public:
    EntrySubsort(const Address &addr) {
      useindex = addr.getSpace()->getIndex(); useoffset = addr.getOffset(); }	///< Construct given a sub-sorting address
    EntrySubsort(void) { useindex=0; useoffset=0; }				///< Construct earliest possible sub-sort

    /// \brief Given a boolean value, construct the earliest/latest possible sub-sort
    ///
    /// \param val is \b true for the latest and \b false for the earliest possible sub-sort
    EntrySubsort(bool val) {
      if (val) { useindex=0xffff; } // Greater than any real values
      else { useindex=0; useoffset=0; }	// Less than any real values
    }
    /// \brief Copy constructor
    EntrySubsort(const EntrySubsort &op2) {
      useindex = op2.useindex;
      useoffset = op2.useoffset;
    }
    /// \brief Compare \b this with another sub-sort
    bool operator<(const EntrySubsort &op2) {
      if (useindex != op2.useindex)
	return (useindex < op2.useindex);
      return (useoffset < op2.useoffset);
    }
  };
  typedef uintb linetype;		///< The linear element for a rangemap of SymbolEntry
  typedef EntrySubsort subsorttype;	///< The sub-sort object for a rangemap
  typedef EntryInitData inittype;	///< Initialization data for a SymbolEntry in a rangemap

  SymbolEntry(uintb a,uintb b);		///< Construct given just the offset range
  SymbolEntry(Symbol *sym,uint4 exfl,uint8 h,int4 off,int4 sz,const RangeList &rnglist);	///< Construct a dynamic SymbolEntry
  bool isPiece(void) const { return ((extraflags&(Varnode::precislo|Varnode::precishi))!=0); }	///< Is \b this a high or low piece of the whole Symbol
  bool isDynamic(void) const { return addr.isInvalid(); }		///< Is \b storage \e dynamic
  bool isInvalid(void) const { return (addr.isInvalid() && (hash==0)); }	///< Is \b this storage \e invalid
  uint4 getAllFlags(void) const;					///< Get all Varnode flags for \b this storage
  int4 getOffset(void) const { return offset; }				///< Get offset of \b this within the Symbol
  uintb getFirst(void) const { return addr.getOffset(); }		///< Get the first offset of \b this storage location
  uintb getLast(void) const { return (addr.getOffset()+size-1); }	///< Get the last offset of \b this storage location
  subsorttype getSubsort(void) const;					///< Get the sub-sort object
  void initialize(const EntryInitData &data);				///< Fully initialize \b this
  Symbol *getSymbol(void) const { return symbol; }			///< Get the Symbol associated with \b this
  const Address &getAddr(void) const { return addr; }			///< Get the starting address of \b this storage
  uint8 getHash(void) const { return hash; }				///< Get the hash used to identify \b this storage
  int4 getSize(void) const { return size; }				///< Get the number of bytes consumed by \b this storage
  bool inUse(const Address &usepoint) const;				///< Is \b this storage valid for the given code address
  const RangeList &getUseLimit(void) const { return uselimit; }		///< Get the std::set of valid code addresses for \b this storage
  Address getFirstUseAddress(void) const;				///< Get the first code address where \b this storage is valid
  void setUseLimit(const RangeList &uselim) { uselimit = uselim; }	///< Set the range of code addresses where \b this is valid
  bool isAddrTied(void) const;						///< Is \b this storage address tied
  bool updateType(Varnode *vn) const;					///< Update a Varnode data-type from \b this
  Datatype *getSizedType(const Address &addr,int4 sz) const;		///< Get the data-type associated with (a piece of) \b this
  void printEntry(std::ostream &s) const;					///< Dump a description of \b this to a stream
  void saveXml(std::ostream &s) const;					///< Save \b this to an XML stream
  List::const_iterator restoreXml(List::const_iterator iter,const AddrSpaceManager *manage);	///< Restore \b this from an XML stream
};
typedef rangemap<SymbolEntry> EntryMap;			///< A rangemap of SymbolEntry

/// \brief The base class for a symbol in a symbol table or scope
///
/// At its most basic, a Symbol is a \b name and a \b data-type.
/// Practically a Symbol knows what Scope its in, how it should be
/// displayed, and the symbols \e category. A category is a subset
/// of symbols that are stored together for quick access.  The
/// \b category field can be:
///    -  -1   for no category
///    -   0   indicates a function parameter
///    -   1   indicates an equate symbol
class Symbol {
  friend class Scope;
  friend class ScopeInternal;
  friend class SymbolCompareName;
protected:
  Scope *scope;			///< The scope that owns this symbol
  std::string name;			///< The local name of the symbol
  uint4 nameDedup;		///< id to distinguish symbols with the same name
  Datatype *type;		///< The symbol's data-type
  uint4 flags;			///< Varnode-like properties of the symbol
				// only typelock,namelock,readonly,externref
				// addrtied, persist inherited from scope
  uint4 dispflags;		///< Flags affecting the display of this symbol
  int2 category;		///< Special category (-1==none 0=parameter 1=equate)
  uint2 catindex;		///< Index within category
  std::vector<std::list<SymbolEntry>::iterator> mapentry;	///< List of storage locations labeled with \b this Symbol
  virtual ~Symbol(void) {}	///< Destructor
  void setDisplayFormat(uint4 val);	///< Set the display format for \b this Symbol
  void checkSizeTypeLock(void);	///< Calculate if \b size_typelock property is on
public:
  /// \brief Possible display (dispflag) properties for a Symbol
  enum {
    force_hex = 1,		///< Force hexadecimal printing of constant symbol
    force_dec = 2,		///< Force decimal printing of constant symbol
    force_oct = 3,		///< Force octal printing of constant symbol
    force_bin = 4,		///< Force binary printing of constant symbol
    force_char = 5,		///< Force integer to be printed as a character constant
    size_typelock = 8	        ///< Only the size of the symbol is typelocked
  };
  /// \brief Construct given a name and data-type
  Symbol(Scope *sc,const std::string &nm,Datatype *ct)
  { scope=sc; name=nm; nameDedup=0; type=ct; flags=0; dispflags=0; category=-1; }

  /// \brief Construct for use with restoreXml()
  Symbol(Scope *sc) { scope=sc; nameDedup=0; flags=0; dispflags=0; category=-1; }

  const std::string &getName(void) const { return name; }		///< Get the local name of the symbol
  Datatype *getType(void) const { return type; }		///< Get the data-type
  uint4 getId(void) const { return (uint4)(uintp)this; }	///< Get a unique id for the symbol
  uint4 getFlags(void) const { return flags; }			///< Get the boolean properties of the Symbol
  uint4 getDisplayFormat(void) const { return (dispflags & 7); }	///< Get the format to display the Symbol in
  int2 getCategory(void) const { return category; }		///< Get the Symbol category
  uint2 getCategoryIndex(void) const { return catindex; }	///< Get the position of the Symbol within its category
  bool isTypeLocked(void) const { return ((flags&Varnode::typelock)!=0); }	///< Is the Symbol type-locked
  bool isNameLocked(void) const { return ((flags&Varnode::namelock)!=0); }	///< Is the Symbol name-locked
  bool isSizeTypeLocked(void) const { return ((dispflags & size_typelock)!=0); }	///< Is the Symbol size type-locked
  bool isIndirectStorage(void) const { return ((flags&Varnode::indirectstorage)!=0); }	///< Is storage really a pointer to the true Symbol
  bool isHiddenReturn(void) const { return ((flags&Varnode::hiddenretparm)!=0); }	///< Is this a reference to the function return value
  bool isNameUndefined(void) const;				///< Does \b this have an undefined name
  Scope *getScope(void) const { return scope; }			///< Get the scope owning \b this Symbol
  SymbolEntry *getFirstWholeMap(void) const;	 		///< Get the first entire mapping of the symbol
  SymbolEntry *getMapEntry(const Address &addr) const;	 	///< Get first mapping of the symbol that contains the given Address
  void saveXmlHeader(std::ostream &s) const;				///< Save basic Symbol properties as XML attributes
  void restoreXmlHeader(const Element *el);			///< Restore basic Symbol properties from XML
  void saveXmlBody(std::ostream &s) const;				///< Save details of the Symbol to XML
  void restoreXmlBody(List::const_iterator iter);		///< Restore details of the Symbol from XML
  virtual void saveXml(std::ostream &s) const;			///< Save \b this Symbol to an XML stream
  virtual void restoreXml(const Element *el);			///< Restore \b this Symbol from an XML stream
};

/// Force a specific display format for constant symbols
/// \param val is the format:  force_hex, force_dec, force_oct, etc.
inline void Symbol::setDisplayFormat(uint4 val)

{
  dispflags &= 0xfffffff8;
  dispflags |= val;
}

/// Retrieve the (union of) Varnode flags specific to the Symbol and specific to \b this storage.
/// \return all Varnode flags that apply
inline uint4 SymbolEntry::getAllFlags(void) const {
  return extraflags | symbol->getFlags();
}

inline bool SymbolEntry::isAddrTied(void) const {
  return ((symbol->getFlags()&Varnode::addrtied)!=0);
}

/// \brief A Symbol representing an executable function
///
/// This Symbol owns the Funcdata object for the function it represents. The formal
/// Symbol is thus associated with all the meta-data about the function.
class FunctionSymbol : public Symbol {
  Funcdata *fd;				///< The underlying meta-data object for the function
  virtual ~FunctionSymbol(void);
  void buildType(int4 size);		///< Build the data-type associated with \b this Symbol
public:
  FunctionSymbol(Scope *sc,const std::string &nm,int4 size);	///< Construct given the name
  FunctionSymbol(Scope *sc,int4 size);			///< Constructor for use with restoreXml
  Funcdata *getFunction(void);				///< Get the underlying Funcdata object
  virtual void saveXml(std::ostream &s) const;
  virtual void restoreXml(const Element *el);
};

/// \brief A Symbol that holds \b equate information for a constant
///
/// This is a symbol that labels a constant. It can either replace the
/// constant's token with the symbol name, or it can force a conversion in
/// the emitted format of the constant.
class EquateSymbol : public Symbol {
  uintb value;				///< Value of the constant being equated
public:
  EquateSymbol(Scope *sc) : Symbol(sc) { value = 0; category = 1; }	///< Constructor for use with restoreXml
  uintb getValue(void) const { return value; }				///< Get the constant value
  bool isValueClose(uintb op2Value,int4 size) const;			///< Is the given value similar to \b this equate
  virtual void saveXml(std::ostream &s) const;
  virtual void restoreXml(const Element *el);
};

/// \brief A Symbol that labels code internal to a function
class LabSymbol : public Symbol {
  void buildType(void);		///< Build placeholder data-type
public:
  LabSymbol(Scope *sc,const std::string &nm);	///< Construct given name
  LabSymbol(Scope *sc);				///< Constructor for use with restoreXml
  virtual void saveXml(std::ostream &s) const;
  virtual void restoreXml(const Element *el);
};

/// \brief A function Symbol referring to an external location
///
/// This Symbol is intended to label functions that have not been mapped directly into
/// the image being analyzed. It holds a level of indirection between the address the
/// image expects the symbol to be at and a \b placeholder address the system hangs
/// meta-data on.
class ExternRefSymbol : public Symbol {
  Address refaddr;			///< The \e placeholder address for meta-data
  void buildNameType(void);		///< Create a name and data-type for the Symbol
  virtual ~ExternRefSymbol(void) {}
public:
  ExternRefSymbol(Scope *sc,const Address &ref,const std::string &nm);	///< Construct given a \e placeholder address
  ExternRefSymbol(Scope *sc) : Symbol(sc) {} 				///< For use with restoreXml
  const Address &getRefAddr(void) const { return refaddr; }		///< Return the \e placeholder address
  virtual void saveXml(std::ostream &s) const;
  virtual void restoreXml(const Element *el);
};

/// \brief Comparator for sorting Symbol objects by name
class SymbolCompareName {
public:
  /// \brief Compare two Symbol pointers
  ///
  /// Compare based on name. Use the deduplication id on the symbols if necessary
  /// \param sym1 is the first Symbol
  /// \param sym2 is the second Symbol
  /// \return \b true if the first is ordered before the second
  bool operator()(const Symbol *sym1,const Symbol *sym2) const {
    int4 comp = sym1->name.compare(sym2->name);
    if (comp < 0) return true;
    if (comp > 0) return false;
    return (sym1->nameDedup < sym2->nameDedup);
  }
};
typedef std::set<Symbol *,SymbolCompareName> SymbolNameTree;		///< A std::set of Symbol objects sorted by name

/// \brief An iterator over SymbolEntry objects in multiple address spaces
///
/// Given an EntryMap (a rangemap of SymbolEntry objects in a single address space)
/// for each address space, iterator over all the SymbolEntry objects
class MapIterator {
  const std::vector<EntryMap *> *map;		///< The std::list of EntryMaps, one per address space
  std::vector<EntryMap *>::const_iterator curmap;	///< Current EntryMap being iterated
  std::list<SymbolEntry>::const_iterator curiter;	///< Current SymbolEntry being iterated
public:
  MapIterator(void) { map = (const std::vector<EntryMap *> *)0; }	///< Construct an uninitialized iterator

  /// \brief Construct iterator at a specific position
  ///
  /// \param m is the std::list of EntryMaps
  /// \param cm is the position of the iterator within the EntryMap std::list
  /// \param ci is the position of the iterator within the specific EntryMap
  MapIterator(const std::vector<EntryMap *> *m,
	       std::vector<EntryMap *>::const_iterator cm,
	       std::list<SymbolEntry>::const_iterator ci) {
    map = m; curmap = cm; curiter = ci;
  }

  /// \brief Copy constructor
  MapIterator(const MapIterator &op2) {
    map = op2.map; curmap = op2.curmap; curiter = op2.curiter;
  }
  const SymbolEntry *operator*(void) const { return &(*curiter); }	///< Return the SymbolEntry being pointed at
  MapIterator &operator++(void);					///< Pre-increment the iterator
  MapIterator operator++(int4 i);					///< Post-increment the iterator

  /// \brief Assignment operator
  MapIterator &operator=(const MapIterator &op2) {
    map = op2.map;
    curmap = op2.curmap;
    curiter = op2.curiter;
    return *this;
  }

  /// \brief Equality operator
  bool operator==(const MapIterator &op2) const {
    if (curmap != op2.curmap) return false;
    if (curmap == map->end()) return true;
    return (curiter==op2.curiter);
  }

  /// \brief Inequality operator
  bool operator!=(const MapIterator &op2) const {
    if (curmap != op2.curmap) return true;
    if (curmap == map->end()) return false;
    return (curiter!=op2.curiter);
  }
};

/// \brief A key for looking up child symbol scopes within a parent, based on name
///
/// A key for mapping from name to Scope.  The class includes a deduplication component
/// if Scopes with the same name are allowed.
class ScopeKey {
  std::string name;			///< The name of the Scope
  uintb dedupId;		///< A duplication id for the Scope
public:
  ScopeKey(const std::string &nm,uint4 id) { name = nm; dedupId = id; }	///< Construct given a name and id
  bool operator<(const ScopeKey &op2) const;				///< Comparison operator
};
typedef std::map<ScopeKey,Scope *> ScopeMap;		///< A std::map from ScopeKey to Scope

/// \brief A collection of Symbol objects within a single (namespace or functional) scope
///
/// This acts as a traditional Symbol container, allowing them to be accessed by name, but
/// it also keeps track of how a Symbol is mapped into memory. It allows a Symbol to be looked up
/// by its location in memory, which is sensitive to the address of the code accessing the Symbol.
///
/// Capabilities include:
///   - Search for Symbols
///      - By name
///      - By storage address
///      - By type of Symbol
///      - Containing a range
///      - Overlapping a range
///   - Insert or remove a Symbol
///   - Add or remove SymbolEntry objects which associate Symbols with storage and the code that accesses it
///   - Modify properties of a Symbol
///
/// A scope also supports the idea of \b ownership of memory. In theory, for a Symbol in the scope, at
/// the code locations where the Symbol storage is valid, the scope \e owns the storage memory. In practice,
/// a Scope object knows about memory ranges where a Symbol might be \e discovered.  For instance, the
/// global Scope usually owns all memory in the \e ram address space.
class Scope {
  friend class Database;
  friend class ScopeCompare;
  RangeList rangetree;				///< Range of data addresses \e owned by \b this scope
  Scope *parent;				///< The parent scope
  ScopeMap children;				///< Sorted std::list of child scopes
  void attachScope(Scope *child);		///< Attach a new child Scope to \b this
  void detachScope(ScopeMap::iterator iter);	///< Detach a child Scope from \b this

protected:
  Architecture *glb;				///< Architecture of \b this scope
  std::string name;					///< Name of \b this scope
  Funcdata *fd;					///< (If non-null) the function which \b this is the local Scope for
  uint4 dedupId;				///< Id to dedup scopes with same name (when allowed)
  static const Scope *stackAddr(const Scope *scope1,
				     const Scope *scope2,
				     const Address &addr,
				     const Address &usepoint,
				     SymbolEntry **addrmatch);
  static const Scope *stackContainer(const Scope *scope1,
					  const Scope *scope2,
					  const Address &addr,int4 size,
					  const Address &usepoint,
					  SymbolEntry **addrmatch);
  static const Scope *stackClosestFit(const Scope *scope1,
					   const Scope *scope2,
					   const Address &addr,int4 size,
					   const Address &usepoint,
					   SymbolEntry **addrmatch);
  static const Scope *stackFunction(const Scope *scope1,
					 const Scope *scope2,
					 const Address &addr,
					 Funcdata **addrmatch);
  static const Scope *stackExternalRef(const Scope *scope1,
					    const Scope *scope2,
					    const Address &addr,
					    ExternRefSymbol **addrmatch);
  static const Scope *stackCodeLabel(const Scope *scope1,
					  const Scope *scope2,
					  const Address &addr,
					  LabSymbol **addrmatch);

  const RangeList &getRangeTree(void) const { return rangetree; }	///< Access the address ranges owned by \b this Scope
  virtual void restrictScope(Funcdata *f);				///< Convert \b this to a local Scope

  // These add/remove range are for scope \b discovery, i.e. we may
  // know an address belongs to a certain scope, without knowing any symbol
  virtual void addRange(AddrSpace *spc,uintb first,uintb last);		///< Add a memory range to the ownership of \b this Scope
  virtual void removeRange(AddrSpace *spc,uintb first,uintb last);	///< Remove a memory range from the ownership of \b this Scope

  /// \brief Put a Symbol into the name std::map
  ///
  /// \param sym is the preconstructed Symbol
  virtual void addSymbolInternal(Symbol *sym)=0;

  /// \brief Create a new SymbolEntry for a Symbol given a memory range
  ///
  /// The SymbolEntry is specified in terms of a memory range and \b usepoint
  /// \param sym is the given Symbol being mapped
  /// \param exfl are any boolean Varnode properties specific to the memory range
  /// \param addr is the starting address of the given memory range
  /// \param off is the byte offset of the new SymbolEntry (relative to the whole Symbol)
  /// \param sz is the number of bytes in the range
  /// \param uselim is the given \b usepoint (which may be \e invalid)
  /// \return the newly created SymbolEntry
  virtual SymbolEntry *addMapInternal(Symbol *sym,uint4 exfl,const Address &addr,int4 off,int4 sz,
				      const RangeList &uselim)=0;


  /// \brief Create a new SymbolEntry for a Symbol given a dynamic hash
  ///
  /// The SymbolEntry is specified in terms of a \b hash and \b usepoint, which describe how
  /// to find the temporary Varnode holding the symbol value.
  /// \param sym is the given Symbol being mapped
  /// \param exfl are any boolean Varnode properties
  /// \param hash is the given dynamic hash
  /// \param off is the byte offset of the new SymbolEntry (relative to the whole Symbol)
  /// \param sz is the number of bytes occupied by the Varnode
  /// \param uselim is the given \b usepoint
  /// \return the newly created SymbolEntry
  virtual SymbolEntry *addDynamicMapInternal(Symbol *sym,uint4 exfl,uint8 hash,int4 off,int4 sz,
					     const RangeList &uselim)=0;
  SymbolEntry *addMap(const SymbolEntry &entry);	///< Integrate a SymbolEntry into the range maps
public:
#ifdef OPACTION_DEBUG
  mutable bool debugon;
  void turnOnDebug(void) const { debugon = true; }
  void turnOffDebug(void) const { debugon = false; }
#endif
  /// \brief Construct an empty scope, given a name and Architecture
  Scope(const std::string &nm,Architecture *g) {
    name = nm; glb = g; parent = (Scope *)0; fd = (Funcdata *)0; dedupId = 0;
#ifdef OPACTION_DEBUG
    debugon = false;
#endif
  }
  virtual ~Scope(void);						///< Destructor
  virtual MapIterator begin(void) const=0;			///< Beginning iterator to mapped SymbolEntrys
  virtual MapIterator end(void) const=0;			///< Ending iterator to mapped SymbolEntrys
  virtual std::list<SymbolEntry>::const_iterator beginDynamic(void) const=0;	///< Beginning iterator to dynamic SymbolEntrys
  virtual std::list<SymbolEntry>::const_iterator endDynamic(void) const=0;	///< Ending iterator to dynamic SymbolEntrys
  virtual std::list<SymbolEntry>::iterator beginDynamic(void)=0;	///< Beginning iterator to dynamic SymbolEntrys
  virtual std::list<SymbolEntry>::iterator endDynamic(void)=0;	///< Ending iterator to dynamic SymbolEntrys
  virtual void clear(void)=0;					///< Clear all symbols from \b this scope
  virtual void clearCategory(int4 cat)=0;			///< Clear all symbols of the given category from \b this scope
  virtual void clearUnlocked(void)=0;				///< Clear all unlocked symbols from \b this scope
  virtual void clearUnlockedCategory(int4 cat)=0;		///< Clear unlocked symbols of the given category from \b this scope

  /// \brief Query if the given range is owned by \b this Scope
  ///
  /// All bytes in the range must be owned, and ownership can be informed by
  /// particular code that is accessing the range.
  /// \param addr is the starting address of the range
  /// \param size is the number of bytes in the range
  /// \param usepoint is the code address at which the given range is being accessed (may be \e invalid)
  /// \return true if \b this Scope owns the memory range
  virtual bool inScope(const Address &addr,int4 size, const Address &usepoint) const {
    return rangetree.inRange(addr,size); }

  virtual void removeSymbol(Symbol *symbol)=0;		///< Remove the given Symbol from \b this Scope
  virtual void renameSymbol(Symbol *sym,const std::string &newname)=0;	///< Rename a Symbol within \b this Scope

  /// \brief Change the data-type of a Symbol within \b this Scope
  ///
  /// If the size of the Symbol changes, any mapping (SymbolEntry) is adjusted
  /// \param sym is the given Symbol
  /// \param ct is the new data-type
  virtual void retypeSymbol(Symbol *sym,Datatype *ct)=0;
  virtual void setAttribute(Symbol *sym,uint4 attr)=0;		///< Set boolean Varnode properties on a Symbol
  virtual void clearAttribute(Symbol *sym,uint4 attr)=0;	///< Clear boolean Varnode properties on a Symbol
  virtual void setDisplayFormat(Symbol *sym,uint4 attr)=0;	///< Set the display format for a Symbol

  // Find routines only search the scope itself

  /// \brief Find a Symbol at a given address and \b usepoint
  ///
  /// \param addr is the given address
  /// \param usepoint is the point at which the Symbol is accessed (may be \e invalid)
  /// \return the matching SymbolEntry or NULL
  virtual SymbolEntry *findAddr(const Address &addr,const Address &usepoint) const=0;

  /// \brief Find the smallest Symbol containing the given memory range
  ///
  /// \param addr is the starting address of the given memory range
  /// \param size is the number of bytes in the range
  /// \param usepoint is the point at which the Symbol is accessed (may be \e invalid)
  /// \return the matching SymbolEntry or NULL
  virtual SymbolEntry *findContainer(const Address &addr,int4 size,
					     const Address &usepoint) const=0;

  /// \brief Find Symbol which is the closest fit to the given memory range
  ///
  /// \param addr is the starting address of the given memory range
  /// \param size is the number of bytes in the range
  /// \param usepoint is the point at which the Symbol is accessed (may be \e invalid)
  /// \return the matching SymbolEntry or NULL
  virtual SymbolEntry *findClosestFit(const Address &addr,int4 size,
					 const Address &usepoint) const=0;

  /// \brief Find the function starting at the given address
  ///
  /// \param addr is the given starting address
  /// \return the matching Funcdata object or NULL
  virtual Funcdata *findFunction(const Address &addr) const=0;

  /// \brief Find an \e external \e reference at the given address
  ///
  /// \param addr is the given address
  /// \return the matching ExternRefSymbol or NULL
  virtual ExternRefSymbol *findExternalRef(const Address &addr) const=0;

  /// \brief Find a label Symbol at the given address
  ///
  /// \param addr is the given address
  /// \return the matching LabSymbol or NULL
  virtual LabSymbol *findCodeLabel(const Address &addr) const=0;

  /// \brief Find first Symbol overlapping the given memory range
  ///
  /// \param addr is the starting address of the given range
  /// \param size is the number of bytes in the range
  /// \return an overlapping SymbolEntry or NULL if none exists
  virtual SymbolEntry *findOverlap(const Address &addr,int4 size) const=0;

  /// \brief Find first Symbol before (but not containing) a given address
  ///
  /// \param addr is the given address
  /// \return the SymbolEntry occurring immediately before or NULL if none exists
  virtual SymbolEntry *findBefore(const Address &addr) const=0;

  /// \brief Find first Symbol after (but not containing) a given address
  ///
  /// \param addr is the given address
  /// \return a SymbolEntry occurring immediately after or NULL if none exists
  virtual SymbolEntry *findAfter(const Address &addr) const=0;

  /// \brief Find a Symbol by name within \b this Scope
  ///
  /// If there are multiple Symbols with the same name, all are passed back.
  /// \param name is the name to search for
  /// \param res will contain any matching Symbols
  virtual void findByName(const std::string &name,std::vector<Symbol *> &res) const=0;

  /// \brief Convert an \e external \e reference to the referenced function
  ///
  /// \param sym is the Symbol marking the external reference
  /// \return the underlying Funcdata object or NULL if none exists
  virtual Funcdata *resolveExternalRefFunction(ExternRefSymbol *sym) const=0;

  /// \brief Given an address and data-type, build a suitable generic symbol name
  ///
  /// \param addr is the given address
  /// \param pc is the address at which the name is getting used
  /// \param ct is a data-type used to inform the name
  /// \param index is a reference to an index used to make the name unique, which will be updated
  /// \param flags are boolean properties of the variable we need the name for
  /// \return the new variable name
  virtual std::string buildVariableName(const Address &addr,
				   const Address &pc,
				   Datatype *ct,int4 &index,uint4 flags) const=0;

  /// \brief Build a formal \b undefined name, used internally when a Symbol is not given a name
  ///
  /// \return a special internal name that won't collide with other names in \b this Scope
  virtual std::string buildUndefinedName(void) const=0;

  /// \brief Produce a version of the given symbol name that won't collide with other names in \b this Scope
  ///
  /// \param nm is the given name
  /// \return return a unique version of the name
  virtual std::string makeNameUnique(const std::string &nm) const=0;

  virtual void saveXml(std::ostream &s) const=0;		///< Write out \b this as a \<scope> XML tag
  virtual void restoreXml(const Element *el)=0;		///< Restore \b this Scope from a \<scope> XML tag
  virtual void printEntries(std::ostream &s) const=0;	///< Dump a description of all SymbolEntry objects to a stream

  /// \brief Get the number of Symbols in the given category
  ///
  /// \param cat is the Symbol \e category
  /// \return the number in that \e category
  virtual int4 getCategorySize(int4 cat) const=0;

  /// \brief Retrieve a Symbol by index within a specific \e category
  ///
  /// \param cat is the Symbol \e category
  /// \param ind is the index (within the category) of the Symbol
  /// \return the indicated Symbol or NULL if no Symbol with that index exists
  virtual Symbol *getCategorySymbol(int4 cat,int4 ind) const=0;

  /// \brief Set the \e category and index for the given Symbol
  ///
  /// \param sym is the given Symbol
  /// \param cat is the \e category to std::set for the Symbol
  /// \param ind is the index position to std::set (within the category)
  virtual void setCategory(Symbol *sym,int4 cat,int4 ind)=0;

  virtual SymbolEntry *addSymbol(const std::string &name,Datatype *ct,
				 const Address &addr,const Address &usepoint);

  const std::string &getName(void) const { return name; }		///< Get the name of the Scope
  bool isGlobal(void) const { return (fd == (Funcdata *)0); }	///< Return \b true if \b this scope is global

  // The main global querying routines
  void queryByName(const std::string &name,std::vector<Symbol *> &res) const;	///< Look-up symbols by name
  Funcdata *queryFunction(const std::string &name) const;			///< Look-up a function by name
  SymbolEntry *queryByAddr(const Address &addr,
			   const Address &usepoint) const;	  	///< Get Symbol with matching address
  SymbolEntry *queryContainer(const Address &addr,int4 size,
			      const Address &usepoint) const;		///< Find the smallest containing Symbol
  SymbolEntry *queryProperties(const Address &addr,int4 size,
			       const Address &usepoint,uint4 &flags) const;	///< Find a Symbol or properties at the given address
  Funcdata *queryFunction(const Address &addr) const;			///< Look-up a function by address
  Funcdata *queryExternalRefFunction(const Address &addr) const;	///< Look-up a function thru an \e external \e reference
  LabSymbol *queryCodeLabel(const Address &addr) const;			///< Look-up a code label by address

  Scope *resolveScope(const std::string &name) const;			///< Find a child Scope of \b this
  Scope *discoverScope(const Address &addr,int4 sz,const Address &usepoint);	///< Find the owning Scope of a given memory range
  ScopeMap::const_iterator childrenBegin() const { return children.begin(); }	///< Beginning iterator of child scopes
  ScopeMap::const_iterator childrenEnd() const { return children.end(); }	///< Ending iterator of child scopes
  void saveXmlRecursive(std::ostream &s,bool onlyGlobal) const;		///< Save all contained scopes as an XML stream
  void overrideSizeLockType(Symbol *sym,Datatype *ct);			///< Change the data-type of a Symbol that is \e sizelocked
  void resetSizeLockType(Symbol *sym);				///< Clear a Symbol's \e size-locked data-type
  bool isSubScope(const Scope *scp) const;			///< Is this a sub-scope of the given Scope
  std::string getFullName(void) const;				///< Get the full name of \b this Scope
  void getNameSegments(std::vector<std::string> &vec) const;		///< Get the fullname of \b this in segments
  Architecture *getArch(void) const { return glb; }		///< Get the Architecture associated with \b this
  Scope *getParent(void) const { return parent; }		///< Get the parent Scope (or NULL if \b this is the global Scope)
  Symbol *addSymbol(const std::string &name,Datatype *ct);		///< Add a new Symbol \e without mapping it to an address
  SymbolEntry *addMapPoint(Symbol *sym,const Address &addr,
			   const Address &usepoint);		///< Map a Symbol to a specific address
  Symbol *addMapSym(const Element *el);				///< Add a mapped Symbol from a \<mapsym> XML tag
  FunctionSymbol *addFunction(const Address &addr,const std::string &nm);
  ExternRefSymbol *addExternalRef(const Address &addr,const Address &refaddr,const std::string &nm);
  LabSymbol *addCodeLabel(const Address &addr,const std::string &nm);
  Symbol *addDynamicSymbol(const std::string &nm,Datatype *ct,const Address &caddr,uint8 hash);
  bool isReadOnly(const Address &addr,int4 size,const Address &usepoint) const;
  void printBounds(std::ostream &s) const { rangetree.printBounds(s); }	///< Print a description of \b this Scope's \e owned memory ranges
};

/// \brief An in-memory implementation of the Scope interface.
///
/// This can act as a stand-alone Scope object or serve as an in-memory cache for
/// another implementation.  This implements a \b nametree, which is a
/// a std::set of Symbol objects (the std::set owns the Symbol objects). It also implements
/// a \b maptable, which is a std::list of rangemaps that own the SymbolEntry objects.
class ScopeInternal : public Scope {
  void processHole(const Element *el);
  void insertNameTree(Symbol *sym);
  SymbolNameTree::const_iterator findFirstByName(const std::string &name) const;
protected:
  virtual void addSymbolInternal(Symbol *sym);
  virtual SymbolEntry *addMapInternal(Symbol *sym,uint4 exfl,const Address &addr,int4 off,int4 sz,const RangeList &uselim);
  virtual SymbolEntry *addDynamicMapInternal(Symbol *sym,uint4 exfl,uint8 hash,int4 off,int4 sz,
					     const RangeList &uselim);
  SymbolNameTree nametree;			///< The std::set of Symbol objects, sorted by name
  std::vector<EntryMap *> maptable;			///< Rangemaps of SymbolEntry, one std::map for each address space
  std::vector<std::vector<Symbol *> > category;		///< References to Symbol objects organized by category
  std::list<SymbolEntry> dynamicentry;		///< Dynamic symbol entries
public:
  ScopeInternal(const std::string &nm,Architecture *g);	///< Construct the Scope
  virtual void clear(void);
  virtual void categorySanity(void);			///< Make sure Symbol categories are sane
  virtual void clearCategory(int4 cat);
  virtual void clearUnlocked(void);
  virtual void clearUnlockedCategory(int4 cat);
  virtual ~ScopeInternal(void);
  virtual MapIterator begin(void) const;
  virtual MapIterator end(void) const;
  virtual std::list<SymbolEntry>::const_iterator beginDynamic(void) const;
  virtual std::list<SymbolEntry>::const_iterator endDynamic(void) const;
  virtual std::list<SymbolEntry>::iterator beginDynamic(void);
  virtual std::list<SymbolEntry>::iterator endDynamic(void);
  virtual void removeSymbol(Symbol *symbol);
  virtual void renameSymbol(Symbol *sym,const std::string &newname);
  virtual void retypeSymbol(Symbol *sym,Datatype *ct);
  virtual void setAttribute(Symbol *sym,uint4 attr);
  virtual void clearAttribute(Symbol *sym,uint4 attr);
  virtual void setDisplayFormat(Symbol *sym,uint4 attr);

  virtual SymbolEntry *findAddr(const Address &addr,const Address &usepoint) const;
  virtual SymbolEntry *findContainer(const Address &addr,int4 size,
					const Address &usepoint) const;
  virtual SymbolEntry *findClosestFit(const Address &addr,int4 size,
					 const Address &usepoint) const;
  virtual Funcdata *findFunction(const Address &addr) const;
  virtual ExternRefSymbol *findExternalRef(const Address &addr) const;
  virtual LabSymbol *findCodeLabel(const Address &addr) const;
  virtual SymbolEntry *findOverlap(const Address &addr,int4 size) const;
  virtual SymbolEntry *findBefore(const Address &addr) const;
  virtual SymbolEntry *findAfter(const Address &addr) const;

  virtual void findByName(const std::string &name,std::vector<Symbol *> &res) const;
  virtual Funcdata *resolveExternalRefFunction(ExternRefSymbol *sym) const;

  virtual std::string buildVariableName(const Address &addr,
				   const Address &pc,
				   Datatype *ct,int4 &index,uint4 flags) const;
  virtual std::string buildUndefinedName(void) const;
  virtual std::string makeNameUnique(const std::string &nm) const;
  virtual void saveXml(std::ostream &s) const;
  virtual void restoreXml(const Element *el);
  virtual void printEntries(std::ostream &s) const;
  virtual int4 getCategorySize(int4 cat) const;
  virtual Symbol *getCategorySymbol(int4 cat,int4 ind) const;
  virtual void setCategory(Symbol *sym,int4 cat,int4 ind);
  static void savePathXml(std::ostream &s,const std::vector<std::string> &vec);	///< Save a path with \<val> tags
  static void restorePathXml(std::vector<std::string> &vec,const Element *el);	///< Restore path from \<val> tags
};

/// \brief An Address range associated with the symbol Scope that owns it
///
/// As part of a rangemap, this forms a std::map from addresses to
/// \e namespace Scopes so that the decompiler can quickly find
/// the \e namespace Scope that holds the Symbol it sees accessed.
class ScopeMapper {
  friend class Database;
  /// \brief Helper class for \e not doing any sub-sorting of overlapping ScopeMapper ranges
  class NullSubsort {
  public:
    NullSubsort(void) {}					///< Constructor
    NullSubsort(bool val) {}					///< Constructor given boolean
    NullSubsort(const NullSubsort &op2) {}			///< Copy constructor
    bool operator<(const NullSubsort &op2) { return false; }	///< Compare operation (does nothing)
  };
public:
  typedef Address linetype;		///< The linear element for a rangemap
  typedef NullSubsort subsorttype;	///< The sub-sort object for a rangemap
  typedef Scope *inittype;		///< Initialization data for a ScopeMapper
private:
  Scope *scope;			///< The Scope owning this address range
  Address first;		///< The first address of the range
  Address last;			///< The last address of the range
public:
  ScopeMapper(Address f,Address l) { first=f; last=l; }		///< Construct given an address range
  Address getFirst(void) const { return first; }		///< Get the first address in the range
  Address getLast(void) const { return last; }			///< Get the last address in the range
  NullSubsort getSubsort(void) const { return NullSubsort(); }	///< Get the sub-subsort object
  Scope *getScope(void) const { return scope; }			///< Get the Scope owning this address range
  void initialize(const inittype &data) { scope = data; }	///< Initialize the range (with the owning Scope)
};
typedef rangemap<ScopeMapper> ScopeResolve;		///< A std::map from address to the owning Scope

/// \brief A manager for symbol scopes for a whole executable
///
/// This is the highest level container for anything related to Scope and Symbol
/// objects, it indirectly holds the Funcdata objects as well, through the FunctionSymbol.
/// It acts as the formal \b symbol \b table for the decompiler. The API is mostly concerned
/// with the management of Scope objects.
///
/// A Scope object is initially registered via attachScope(), then it can looked up by name.
/// This class maintains the cross Scope search by address capability, implemented as a
/// std::map from an Address to the Scope that owns it.  For efficiency, this std::map is really
/// only applied to \e namespace Scopes, the global Scope and function Scopes are not
/// entered in the std::map.  This class also maintains a std::set of boolean properties that label
/// memory ranges.  This allows important properties like \e read-only and \e volatile to
/// be put down even if the Symbols aren't yet known.
class Database {
  Architecture *glb;			///< The Architecture to which this symbol table is attached
  Scope *globalscope;			///< A quick reference to the \e global Scope
  ScopeResolve resolvemap;		///< The Address to \e namespace std::map
  partmap<Address,uint4> flagbase;	///< Map of global properties
  void clearResolve(Scope *scope);	///< Clear the \e ownership ranges associated with the given Scope
  void clearResolveRecursive(Scope *scope);	///< Clear the \e ownership ranges of a given Scope and its children
  void fillResolve(Scope *scope);	///< Add the \e ownership ranges of the given Scope to the std::map
  static void parseParentTag(const Element *el,std::string &name,std::vector<std::string> &parnames);
public:
  Database(Architecture *g) { glb=g; globalscope=(Scope *)0; flagbase.defaultValue() = 0; }	///< Constructor
  ~Database(void);						///< Destructor
  Architecture *getArch(void) const { return glb; }		///< Get the Architecture associate with \b this
  void attachScope(Scope *newscope,Scope *parent);		///< Register a new Scope
  void deleteScope(Scope *scope);				///< Delete the given Scope and all its sub-scopes
  void deleteSubScopes(Scope *scope);				///< Delete all sub-scopes of the given Scope
  void clearUnlocked(Scope *scope);				///< Clear unlocked Symbols owned by the given Scope
  void setRange(Scope *scope,const RangeList &rlist);		///< Set the \e ownership range for a Scope
  void addRange(Scope *scope,AddrSpace *spc,uintb first,uintb last);	///< Add an address range to the \e ownership of a Scope
  void removeRange(Scope *scope,AddrSpace *spc,uintb first,uintb last);	///< Remove an address range from \e ownership of a Scope
  Scope *getGlobalScope(void) const { return globalscope; }	///< Get the global Scope
  Scope *resolveScope(const std::vector<std::string> &subnames) const;	///< Look-up a Scope by name
  Scope *resolveScopeSymbolName(const std::string &fullname,const std::string &delim,std::string &basename,Scope *start) const;
  const Scope *mapScope(const Scope *qpoint,const Address &addr,const Address &usepoint) const;
  Scope *mapScope(Scope *qpoint,const Address &addr,const Address &usepoint);
  uint4 getProperty(const Address &addr) const { return flagbase.getValue(addr); }	///< Get boolean properties at the given address
  void setPropertyRange(uint4 flags,const Range &range);	///< Set boolean properties over a given memory range
  void setProperties(const partmap<Address,uint4> &newflags) { flagbase = newflags; }	///< Replace the property std::map
  const partmap<Address,uint4> &getProperties(void) const { return flagbase; }	///< Get the entire property std::map
  void saveXml(std::ostream &s) const;				///< Save the whole Database to an XML stream
  void restoreXml(const Element *el);				///< Recover the whole database from XML
  void restoreXmlScope(const Element *el,Scope *new_scope);	///< Register and fill out a single Scope from XML
};
}

#endif
