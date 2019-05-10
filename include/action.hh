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
/// \file action.hh
/// \brief Action, Rule, and other associates classes supporting transformations on function data-flow
#ifndef __CPUI_ACTION__
#define __CPUI_ACTION__

#include "block.hh"

#include <set>
#include <string>

namespace GhidraDec {

/// \brief The list of groups defining a \e root Action
///
/// Any Rule or \e leaf Action belongs to a \b group. This class
/// is a \b grouplist defined by a collection of these \b group names.
/// The set of Rule and Action objects belong to any of the groups in this list
/// together form a \b root Action.
class ActionGroupList {
  friend class ActionDatabase;
  std::set<std::string> list;		///< List of group names
public:
  /// \brief Check if \b this ActionGroupList contains a given group
  ///
  /// \param nm is the given group to check for
  /// \return true if \b this contains the group
  bool contains(const std::string &nm) const { return (list.find(nm)!=list.end()); }
};

class Rule;

/// \brief Large scale transformations applied to the varnode/op graph
///
/// The base for objects that make changes to the syntax tree of a Funcdata
/// The action is invoked through the apply(Funcdata &data) method.
/// This base class keeps track of basic statistics about how the action is
/// being applied.  Derived classes indicate that a change has been applied
/// by incrementing the \b count field.
/// With OPACTION_DEBUG macro defined, actions support a break point debugging in console mode.
class Action {
public:
  /// Boolean behavior properties governing this particular Action
  enum ruleflags {
    rule_repeatapply = 4,	///< Apply rule repeatedly until no change
    rule_onceperfunc = 8,	///< Apply rule once per function
    rule_oneactperfunc = 16,	///< Makes a change only once per function
    rule_debug = 32,		///< Print debug messages specifically for this action
    rule_warnings_on = 64,	///< If this action makes a change, issue a warning
    rule_warnings_given = 128	///< A warning has been issued for this action
  };
  /// Boolean properties describing the \e status of an action
  enum statusflags {
    status_start=1,		///< At start of action
    status_breakstarthit=2,	///< At start after breakpoint
    status_repeat=4,		///< Repeating the same action
    status_mid=8,		///< In middle of action (use subclass status)
    status_end=16,		///< getFuncdata has completed once (for onceperfunc)
    status_actionbreak=32	///< Completed full action last time but indicated action break
  };
  /// Break points associated with an Action
  enum breakflags {
    break_start = 1,		///< Break at beginning of action
    tmpbreak_start = 2,		///< Temporary break at start of action
    break_action = 4,		///< Break if a change has been made
    tmpbreak_action = 8
  };
protected:
  int4 lcount;			///< Changes not including last call to apply()
  int4 count;			///< Number of changes made by this action so far
  uint4 status;			///< Current status
  uint4 breakpoint;		///< Breakpoint properties
  uint4 flags;			///< Behavior properties
  uint4 count_tests;		///< Number of times apply() has been called
  uint4 count_apply;		///< Number of times apply() made changes
  std::string name;			///< Name of the action
  std::string basegroup;		///< Base group this action belongs to
  void issueWarning(Architecture *glb);	///< Warn that this Action has applied
  bool checkStartBreak(void);	///< Check start breakpoint
  bool checkActionBreak(void);	///< Check action breakpoint
  void turnOnWarnings(void) { flags |= rule_warnings_on; }	///< Enable warnings for this Action
  void turnOffWarnings(void) { flags &= ~rule_warnings_on; }	///< Disable warnings for this Action
public:
  Action(uint4 f,const std::string &nm,const std::string &g);		///< Base constructor for an Action
  virtual ~Action(void) {}					///< Destructor
#ifdef OPACTION_DEBUG
  virtual bool turnOnDebug(const std::string &nm);			///< Turn on debugging
  virtual bool turnOffDebug(const std::string &nm);			///< Turn off debugging
#endif
  virtual void printStatistics(ostream &s) const;		///< Dump statistics to stream
  int4 perform(Funcdata &data); 				///< Perform this action (if necessary)
  bool setBreakPoint(uint4 tp,const std::string &specify);		///< Set a breakpoint on this action
  bool setWarning(bool val,const std::string &specify);		///< Set a warning on this action
  bool disableRule(const std::string &specify);			///< Disable a specific Rule within \b this
  bool enableRule(const std::string &specify);			///< Enable a specific Rule within \b this
  const std::string &getName(void) const { return name; }		///< Get the Action's name
  const std::string &getGroup(void) const { return basegroup; }	///< Get the Action's group
  uint4 getStatus(void) const { return status; }		///< Get the current status of \b this Action
  uint4 getNumTests(void) { return count_tests; }		///< Get the number of times apply() was invoked
  uint4 getNumApply(void) { return count_apply; }		///< Get the number of times apply() made changes
  /// \brief Clone the Action
  ///
  /// If \b this Action is a member of one of the groups in the grouplist,
  /// this returns a clone of the Action, otherwise NULL is returned.
  /// \param grouplist is the list of groups being cloned
  /// \return the cloned Action or NULL
  virtual Action *clone(const ActionGroupList &grouplist) const=0;
  virtual void reset(Funcdata &data);				///< Reset the Action for a new function
  virtual void resetStats(void);				///< Reset the statistics
  /// \brief Make a single attempt to apply \b this Action
  ///
  /// This is the main entry point for applying changes to a function that
  /// are specific to \b this Action. The method can inspect whatever it wants
  /// to decide if the Action does or does not apply. Changes
  /// are indicated by incrementing the \b count field.
  /// \param data is the function to inspect/modify
  /// \return 0 for a complete application, -1 for a partial completion (due to breakpoint)
  virtual int4 apply(Funcdata &data)=0;
  virtual int4 print(ostream &s,int4 num,int4 depth) const;	///< Print a description of this Action to stream
  virtual void printState(ostream &s) const;			///< Print status to stream
  virtual void saveXml(ostream &s) const {} 			///< Save specifics of this action to stream
  virtual void restoreXml(const Element *el,Funcdata *fd) {}	///< Load specifics of action from XML
  virtual Action *getSubAction(const std::string &specify);		///< Retrieve a specific sub-action by name
  virtual Rule *getSubRule(const std::string &specify);		///< Retrieve a specific sub-rule by name
};

/// \brief A group of actions (generally) applied in sequence
///
/// This is a a list of Action objects, which are usually applied in sequence.
/// But the behavior properties of each individual Action may affect this.
/// Properties (like rule_repeatapply) may be put directly to this group
/// that also affect how the Actions are applied.
class ActionGroup : public Action {
protected:
  vector<Action *> list;				///< List of actions to perform in the group
  vector<Action *>::iterator state;			///< Current action being applied
public:
  ActionGroup(uint4 f,const std::string &nm) : Action(f,nm,"") {}	///< Construct given properties and a name
  virtual ~ActionGroup(void);				///< Destructor
  void addAction(Action *ac);				///< Add an Action to the group
  virtual Action *clone(const ActionGroupList &grouplist) const;
  virtual void reset(Funcdata &data);
  virtual void resetStats(void);
  virtual int4 apply(Funcdata &data);
  virtual int4 print(ostream &s,int4 num,int4 depth) const;
  virtual void printState(ostream &s) const;
  virtual Action *getSubAction(const std::string &specify);
  virtual Rule *getSubRule(const std::string &specify);
#ifdef OPACTION_DEBUG
  virtual bool turnOnDebug(const std::string &nm);
  virtual bool turnOffDebug(const std::string &nm);
#endif
  virtual void printStatistics(ostream &s) const;
};

/// \brief Action which checks if restart (sub)actions have been generated
/// and restarts itself.
///
/// Actions or Rules can request a restart on a Funcdata object by calling
/// setRestartPending(true) on it. This action checks for the request then
/// resets and reruns the group of Actions as appropriate.
class ActionRestartGroup : public ActionGroup {
  int4 maxrestarts;			///< Maximum number of restarts allowed
  int4 curstart;			///< Current restart iteration
public:
  ActionRestartGroup(uint4 f,const std::string &nm,int4 max) :
    ActionGroup(f,nm) { maxrestarts = max; }	///< Construct this providing maximum number of restarts
  virtual Action *clone(const ActionGroupList &grouplist) const;
  virtual void reset(Funcdata &data);
  virtual int4 apply(Funcdata &data);
};

/// \brief Class for performing a single transformation on a PcodeOp or Varnode
///
/// A Rule, through its applyOp() method, is handed a specific PcodeOp as a potential
/// point to apply. It determines if it can apply at that point, then makes any changes.
/// Rules inform the system of what types of PcodeOps they can possibly apply to through
/// the getOpList() method. A set of Rules are pooled together into a single Action via
/// the ActionPool, which efficiently applies each Rule across a whole function.
/// A Rule supports the same breakpoint properties as an Action.
/// A Rule is allowed to keep state that is specific to a given function (Funcdata).
/// The reset() method is invoked to purge this state for each new function to be transformed.
class Rule {
public:
  /// Properties associated with a Rule
  enum typeflags {
    type_disable = 1,		///< Is this rule disabled
    rule_debug = 2,		///< Print debug info specific for this rule
    warnings_on = 4,		///< A warning is issued if this rule is applied
    warnings_given = 8		///< Set if a warning for this rule has been given before
  };
private:
  friend struct ActionPool;
  uint4 flags;			///< Properties enabled with \b this Rule
  uint4 breakpoint;		///< Breakpoint(s) enabled for \b this Rule
  std::string name;			///< Name of the Rule
  std::string basegroup;		///< Group to which \b this Rule belongs
  uint4 count_tests;		///< Number of times \b this Rule has attempted to apply
  uint4 count_apply;		///< Number of times \b this Rule has successfully been applied
  void issueWarning(Architecture *glb);	///< If enabled, print a warning that this Rule has been applied
public:
  Rule(const std::string &g,uint4 fl,const std::string &nm);		///< Construct given group, properties name
  virtual ~Rule(void) {}					///< Destructor
  const std::string &getName(void) const { return name; }		///< Return the name of \b this Rule
  const std::string &getGroup(void) const { return basegroup; }	///< Return the group \b this Rule belongs to
  uint4 getNumTests(void) { return count_tests; }		///< Get number of attempted applications
  uint4 getNumApply(void) { return count_apply; }		///< Get number of successful applications
  void setBreak(uint4 tp) { breakpoint |= tp; }			///< Set a breakpoint on \b this Rule
  void clearBreak(uint4 tp) { breakpoint &= ~tp; }		///< Clear a breakpoint on \b this Rule
  void turnOnWarnings(void) { flags |= warnings_on; }		///< Enable warnings for \b this Rule
  void turnOffWarnings(void) { flags &= ~warnings_on; }		///< Disable warnings for \b this Rule
  bool isDisabled(void) const { return ((flags & type_disable)!=0); }	///< Return \b true if \b this Rule is disabled
  void setDisable(void) { flags |= type_disable; }		///< Disable this Rule (within its pool)
  void clearDisable(void) { flags &= ~type_disable; }		///< Enable this Rule (within its pool)
  bool checkActionBreak(void);					///< Check if an action breakpoint is turned on
  uint4 getBreakPoint(void) const { return breakpoint; }	///< Return breakpoint toggles

  /// \brief Clone the Rule
  ///
  /// If \b this Rule is a member of one of the groups in the grouplist,
  /// this returns a clone of the Rule, otherwise NULL is returned.
  /// \param grouplist is the list of groups being cloned
  /// \return the cloned Rule or NULL
  virtual Rule *clone(const ActionGroupList &grouplist) const=0;
  virtual void getOpList(vector<uint4> &oplist) const;		///< List of op codes this rule operates on

  /// \brief Attempt to apply \b this Rule
  ///
  /// This method contains the main logic for applying the Rule. It must use a given
  /// PcodeOp as the point at which the Rule applies. If it does apply,
  /// changes are made directly to the function and 1 (non-zero) is returned, otherwise 0 is returned.
  /// \param op is the given PcodeOp where the Rule may apply
  /// \param data is the function to which to apply
  virtual int4 applyOp(PcodeOp *op,Funcdata &data) { return 0; }
  virtual void reset(Funcdata &data);				///< Reset \b this Rule
  virtual void resetStats(void);				///< Reset Rule statistics
  virtual void printStatistics(ostream &s) const;		///< Print statistics for \b this Rule
#ifdef OPACTION_DEBUG
  virtual bool turnOnDebug(const std::string &nm);			///< Turn on debugging
  virtual bool turnOffDebug(const std::string &nm);			///< Turn off debugging
#endif
};

/// \brief A pool of Rules that apply simultaneously
///
/// This class groups together a set of Rules as a formal Action.
/// Rules are given an opportunity to apply to every PcodeOp in a function.
/// Usually rule_repeatapply is enabled for this action, which causes
/// all Rules to apply repeatedly until no Rule can make an additional change.
class ActionPool : public Action {
  vector<Rule *> allrules;				///< The set of Rules in this ActionPool
  vector<Rule *> perop[CPUI_MAX];			///< Rules associated with each OpCode
  PcodeOpTree::const_iterator op_state; 		///< Current PcodeOp up for rule application
  int4 rule_index;					///< Iterator over Rules for one OpCode
  int4 processOp(PcodeOp *op,Funcdata &data);		///< Apply the next possible Rule to a PcodeOp
public:
  ActionPool(uint4 f,const std::string &nm) : Action(f,nm,"") {}	///< Construct providing properties and name
  virtual ~ActionPool(void);				///< Destructor
  void addRule(Rule *rl);				///< Add a Rule to the pool
  virtual Action *clone(const ActionGroupList &grouplist) const;
  virtual void reset(Funcdata &data);
  virtual void resetStats(void);
  virtual int4 apply(Funcdata &data);
  virtual int4 print(ostream &s,int4 num,int4 depth) const;
  virtual void printState(ostream &s) const;
  virtual Rule *getSubRule(const std::string &specify);
  virtual void printStatistics(ostream &s) const;
#ifdef OPACTION_DEBUG
  virtual bool turnOnDebug(const std::string &nm);
  virtual bool turnOffDebug(const std::string &nm);
#endif
};

/// \brief Database of root Action objects that can be used to transform a function
///
/// This is a container for Action objects. It also manages \b root Action objects,
/// which encapsulate a complete transformation system that can be applied to functions.
/// \e Root Action objects are derived from a single \b universal Action object that
/// has every possible sub-action within it.  A \e root Action has its own name and
/// is derived from the \e universal via a grouplist, which lists a particular subset of
/// Action and Rule groups to use for the root.  A new \e root Action is created by
/// providing a new grouplist via setGroup() or modifying an existing grouplist.
/// This class is intended to be instantiated as a singleton and keeps track of
/// the \e current root Action, which is the one that will be actively applied to functions.
class ActionDatabase {
  Action *currentact;				///< This is the current root Action
  std::string currentactname;			///< The name associated with the current root Action
  map<std::string,ActionGroupList> groupmap;		///< Map from root Action name to the grouplist it uses
  map<std::string,Action *> actionmap;		///< Map from name to root Action
  static const char universalname[];		///< The name of the \e universal root Action
  void registerAction(const std::string &nm,Action *act);	///< Register a \e root Action
  Action *getAction(const std::string &nm) const;				///< Look up a \e root Action by name
  Action *deriveAction(const std::string &baseaction,const std::string &grp);	///< Derive a \e root Action
public:
  ActionDatabase(void) { currentact = (Action *)0; }	///< Constructor
  ~ActionDatabase(void);				///< Destructor
  void registerUniversal(Action *act);			///< Register the \e universal root Action
  Action *getCurrent(void) const { return currentact; }	///< Get the current \e root Action
  const std::string &getCurrentName(void) const { return currentactname; }	///< Get the name of the current \e root Action
  const ActionGroupList &getGroup(const std::string &grp) const;	///< Get a specific grouplist by name
  Action *setCurrent(const std::string &actname);		///< Set the current \e root Action
  Action *toggleAction(const std::string &grp,const std::string &basegrp,bool val);	///< Toggle a group of Actions with a \e root Action

  void setGroup(const std::string &grp,const char **argv);			///< Establish a new \e root Action
  void cloneGroup(const std::string &oldname,const std::string &newname);		///< Clone a \e root Action
  bool addToGroup(const std::string &grp,const std::string &basegroup);		///< Add a group to a \e root Action
  bool removeFromGroup(const std::string &grp,const std::string &basegroup);	///< Remove a group from a \e root Action
};

} // namespace GhidraDec

#endif
