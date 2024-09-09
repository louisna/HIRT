// -*- c-basic-offset: 4 -*-
#ifndef PathThreadSched_HH
#define PathThreadSched_HH
#include <click/element.hh>
#include <click/standard/threadsched.hh>
CLICK_DECLS

/*
 * =c
 * PathThreadSched(ELEMENT THREAD, ...)
 * =s threads
 * specifies element and thread scheduling parameters
 * =d
 * Statically binds elements to threads. If more than one PathThreadSched
 * is specified, they will all run. The one that runs later may override an
 * earlier run.
 *
 * If Click is compiled with NUMA support (libnuma was found at configure time) one can use the format socket/core such as 1/3 which will use the 3rd core of the first NUMA socket.
 *
 * =a
 * ThreadMonitor, BalancedThreadSched
 */

class PathThreadSched : public Element, public ThreadSched { public:

    PathThreadSched() CLICK_COLD;
    ~PathThreadSched() CLICK_COLD;

    const char *class_name() const override	{ return "PathThreadSched"; }

    int configure(Vector<String> &, ErrorHandler *) CLICK_COLD;
    int initialize(ErrorHandler *) CLICK_COLD;

    int initial_home_thread_id(const Element *e);

    Bitvector assigned_thread();

  private:
    Vector<int> _thread_preferences;
    ThreadSched *_next_thread_sched;

    bool set_preference(int eindex);
};

CLICK_ENDDECLS
#endif
