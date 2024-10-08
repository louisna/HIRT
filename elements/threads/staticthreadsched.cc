/*
 * staticthreadsched.{cc,hh} -- element statically assigns tasks to threads
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
#include "staticthreadsched.hh"
#include <click/task.hh>
#include <click/master.hh>
#include <click/router.hh>
#include <click/error.hh>
#include <click/args.hh>
#if HAVE_NUMA
#include <click/numa.hh>
#endif

CLICK_DECLS

StaticThreadSched::StaticThreadSched()
    : _next_thread_sched(0)
{
}

StaticThreadSched::~StaticThreadSched()
{
}

bool StaticThreadSched::set_preference(int eindex, int preference) {
    if (eindex >= _thread_preferences.size())
        _thread_preferences.resize(eindex + 1, THREAD_UNKNOWN);
    _thread_preferences[eindex] = preference;
    return true;
}

int
StaticThreadSched::configure(Vector<String> &conf, ErrorHandler *errh)
{
    String ename;
    String c_preference;
    for (int i = 0; i < conf.size(); i++) {
        if (Args(this, errh).push_back_words(conf[i])
            .read_mp("ELEMENT", ename)
            .read_mp("THREAD", c_preference)
            .complete() < 0)
            return -1;
        Vector<String> pref = c_preference.split('/');
        int preference;
        if (pref.size() > 1) {
            int socket;
            if (!IntArg().parse(pref[0],socket,errh))
                return -1;
            if (!IntArg().parse(pref[1],preference,errh))
                return -1;
#if HAVE_NUMA
            Bitvector b((int)click_max_cpu_ids());
            auto bc = Numa::node_to_cpus(socket);
            bc.toBitvector(b);
            int idx = 0;
            if (b[idx] && preference == 0) {

            } else {

                while (true) {
                    if (b[idx]) {
                        if (preference == 0)
                            break;
                        preference--;
                    }

                    idx++;
                    if (idx >= b.size()) {
                        errh->warning("Socket %d has no usable core %s",socket,pref[1].c_str());
                        idx = 0;
                        break;
                    }
                }
            }
            preference =idx;

#else
            return errh->error("Syntax SOCKET/CORE is only allowed when Click is compiled with NUMA support");

#endif
        }
        else {
            if (!IntArg().parse(pref[0],preference,errh))
                return -1;
        }
        if (preference <= -master()->nthreads() || preference >= master()->nthreads()) {
            errh->warning("thread preference %d out of range", preference);
            preference = (preference < 0 ? -1 : 0);
        }
        bool set = false;
        if (preference < 0)
            preference = master()->nthreads() + preference;
        if (Element* e = router()->find(ename, this))
            set = set_preference(e->eindex(), preference);
        else if (ename) {
            ename = router()->ename_context(eindex()) + ename + "/";
            for (int i = 0; i != router()->nelements(); ++i)
                if (router()->ename(i).starts_with(ename))
                    set = set_preference(i, preference);
        }
        if (!set)
            Args(this, errh).error("%<%s%> does not name an element", ename.c_str());
    }
    _next_thread_sched = router()->thread_sched();
    router()->set_thread_sched(this);
    return 0;
}

Bitvector StaticThreadSched::assigned_thread() {
    Bitvector v(master()->nthreads(),0);
    if (_next_thread_sched) {
        v = _next_thread_sched->assigned_thread();
    }
    for (int i = 0; i < _thread_preferences.size(); i++) {
        if (_thread_preferences[i] != THREAD_UNKNOWN) {
            if (v.size() <= _thread_preferences[i])
                v.resize(_thread_preferences[i]+1);
            v[_thread_preferences[i]] = true;
        }
    }
    return v;
}

int
StaticThreadSched::initial_home_thread_id(const Element *e)
{
    int eidx = e->eindex();
    if (eidx >= 0 && eidx < _thread_preferences.size()
	    && _thread_preferences[eidx] != THREAD_UNKNOWN)
	return _thread_preferences[eidx];
    if (_next_thread_sched)
	return _next_thread_sched->initial_home_thread_id(e);
    else
	return THREAD_UNKNOWN;
}

CLICK_ENDDECLS
EXPORT_ELEMENT(StaticThreadSched)
