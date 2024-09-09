/*
 * PathThreadSched.{cc,hh} -- element statically assigns tasks to threads
 * Eddie Kohler
 *
 * Copyright (c) 2004-2008 Regents of the University of California
 * Copyright (c) 2004-2014 Click authors
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, subject to the conditions
 * listed in the Click LICENSE file. These conditions include: you must
 * preserve this copyright notice, and you cannot mention the copyright
 * holders in advertising related to the Software without their permission.
 * The Software is provided WITHOUT ANY WARRANTY, EXPRESS OR IMPLIED. This
 * notice is a summary of the Click LICENSE file; the license in that file is
 * legally binding.
 */
#include <click/config.h>
#include "paththreadsched.hh"
#include <click/task.hh>
#include <click/master.hh>
#include <click/router.hh>
#include <click/error.hh>
#include <click/args.hh>
#if HAVE_NUMA
#include <click/numa.hh>
#endif

CLICK_DECLS

PathThreadSched::PathThreadSched()
    : _next_thread_sched(0)
{
}

PathThreadSched::~PathThreadSched()
{
}

bool PathThreadSched::set_preference(int eindex) {
    if (eindex >= _thread_preferences.size()) {
      _thread_preferences.resize(eindex + 1, THREAD_UNKNOWN);
    }
    _thread_preferences[eindex] = THREAD_AUTO;
    //_thread_preferences.push_back(eindex);
    return true;
}

int
PathThreadSched::configure(Vector<String> &conf, ErrorHandler *errh)
{
    String ename;
    String c_preference;
    for (int i = 0; i < conf.size(); i++) {
        if (Args(this, errh).push_back_words(conf[i])
            .read_mp("ELEMENT", ename)
            .complete() < 0)
            return -1;
      
        int set;
        
        if (Element* e = router()->find(ename, this)) {
            set = set_preference(e->eindex());
        } else if (ename) {
            ename = router()->ename_context(eindex()) + ename + "/";
            for (int i = 0; i != router()->nelements(); ++i)
                if (router()->ename(i).starts_with(ename))
                    set = set_preference(i);
        }
        if (!set) {
            Args(this, errh).error("%<%s%> does not name an element", ename.c_str());
        }
    }
    _next_thread_sched = router()->thread_sched();
    router()->set_thread_sched(this);

    return 0;
}

int
PathThreadSched::initialize(ErrorHandler *errh)
{
    click_chatter("Initializeing %p{element}", this);
    for (int i = 0; i < _thread_preferences.size(); i++) {
        click_chatter("%d/%d", i, _thread_preferences.size());
        if (_thread_preferences[i] != THREAD_AUTO)
            continue;
        Bitvector p = router()->element(i)->get_passing_threads();
        if (p.weight() > 1) {
            errh->warning("Element %p{element} has more than one passing thread!", this);
        }
        click_chatter("%p{element} : Thread %d", this, p.clz());
        _thread_preferences[i] = p.clz();
    }
    return 0;
}


Bitvector PathThreadSched::assigned_thread() {
    Bitvector v(master()->nthreads(),0);
    if (_next_thread_sched) {
        v = _next_thread_sched->assigned_thread();
    }
    /*for (int i = 0; i < _thread_preferences.size(); i++) {
        if (_thread_preferences[i] != THREAD_UNKNOWN) {
            if (v.size() <= _thread_preferences[i])
                v.resize(_thread_preferences[i]+1);
            v[_thread_preferences[i]] = true;
        }
    }*/
    return v;
}

int
PathThreadSched::initial_home_thread_id(const Element *e)
{
    click_chatter("Assigning home thread of %p{element}", e);
    int eidx = e->eindex();
    ErrorHandler* errh = ErrorHandler::default_handler();
    if (eidx >= 0 && eidx < _thread_preferences.size() )  {
        if (_thread_preferences[eidx] >= 0) {
            return _thread_preferences[eidx];
        }
    }
    /*
	&& _thread_preferences[eidx] != THREAD_UNKNOWN)
	return _thread_preferences[eidx];*/
    if (_next_thread_sched)
	    return _next_thread_sched->initial_home_thread_id(e);

   
	return THREAD_UNKNOWN;
}

CLICK_ENDDECLS
EXPORT_ELEMENT(PathThreadSched)
