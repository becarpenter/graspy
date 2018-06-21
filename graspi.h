// Draft header file for GRASP API in C
// For background see draft-ietf-anima-grasp-api

#include <stdbool.h>
#include <stdint-gcc.h>
#include <string.h>        // Not used here but probably needed...

// Generic types

#ifndef in6_addr
typedef struct {
    uint8_t s6_addr[16];   // could use IPv4-mapped in here too
    } in6_addr;
#endif

#ifndef bool
typedef enum { false, true } bool;
#endif

// Types for GRASP API

typedef uint32_t asa_nonce;

// We want all strings to have an associated length field, as an aid
// to buffer overflow prevention. But if there's a good string library
// available, use that instead.

typedef struct {
    int st_size;
    unsigned char st_value[];     // UTF-8 bytes, null terminated at st_value[st_size] so
                                  // malloc() at least one spare byte
    } gstring;

typedef struct {
    uint32_t id_value;
    in6_addr source;
    } session_nonce;

typedef struct {
    in6_addr a_locator; // if is_ipaddress
    gstring s_locator;  // if (is_fqdn || is_uri)
    int protocol;
    int port;
    int ifi;
    uint32_t expire;
    bool diverted, is_ipaddress, is_fqdn, is_uri;
    } asa_locator;

typedef struct {
    gstring name;
    uint8_t flags;            // encode as in GRASP spec
    int loop_count;
    int value_size;           // size of value
    uint8_t *cbor_value[];    // CBOR bytestring of value;
                              // user must do malloc() and free()
    } objective;

typedef struct {
    objective obj;
    asa_locator source;
    } tagged_objective;

// GRASP API function declarations follow
// They return 0 for success and an error code >0 for failure.

// Non-blocking variants could return noReply (2) if no reply yet

int  register_asa(asa_name, nonce)
     gstring asa_name;
     asa_nonce *nonce;
     {}

int  deregister_asa(asa_name, nonce)
     gstring asa_name;
     asa_nonce nonce;
     {}

int  register_obj(nonce, obj, ttl, discoverable, overlap, local)
     asa_nonce nonce;
     objective obj;
     uint32_t ttl;
     bool discoverable, overlap, local;  // Should be false by default
     {}

int  deregister_obj(nonce, obj)
     asa_nonce nonce;
     objective obj;
     {}

int  discover(nonce, obj, timeout, flush, relay_ifi, count, locators)
     asa_nonce nonce;
     objective obj;
     uint32_t timeout;
     bool flush, relay_ifi;       // Should be false by default
     int *count;                  // count of discovered locators (zero if none) 
     asa_locator *locators[];     // array of asa_locator
                                  // The user must free(locators) asap.
     {}

int  req_negotiate(anonce, obj, peer, timeout, snonce, robj, reason)
     asa_nonce anonce;
     objective obj;               // proffered objective
     asa_locator peer;
     uint32_t timeout;
     session_nonce *snonce;       // may be 0,0
     objective *robj;             // counter-offered objective
     gstring *reason;             // reason string for failed negotiation
     {}

int  negotiate_step(anonce, snonce, obj, timeout, robj, reason)
     asa_nonce anonce;
     session_nonce snonce;
     objective obj;               // proffered objective
     uint32_t timeout;
     objective *robj;             // counter-offered objective
     gstring *reason;             // reason string for failed negotiation
     {}

int  negotiate_wait(anonce, snonce, timeout)
     asa_nonce anonce;
     session_nonce snonce;
     uint32_t timeout;
     {}

int  end_negotiate(anonce, snonce, result, reason)
     asa_nonce anonce;
     session_nonce snonce;
     bool result;
     gstring reason;            // May be ''
     {}

int  listen_negotiate(anonce, obj, snonce, robj)
     asa_nonce anonce;
     objective obj;               // named objective
     session_nonce *snonce;
     objective *robj;             // requested objective
     {}

int  stop_negotiate(anonce, obj)
     asa_nonce anonce;
     objective obj;               // named objective
     {}

int  synchronize(anonce, obj, peer, timeout, robj)
     asa_nonce anonce;
     objective obj;               // named objective
     asa_locator peer;
     uint32_t timeout;
     objective *robj;             // synchronized objective
     {}

int  listen_synchronize(anonce, obj)
     asa_nonce anonce;
     objective obj;               // objective to be sent
     {}

int  stop_synchronize(anonce, obj)
     asa_nonce anonce;
     objective obj;               // named objective
     {}

int  flood(anonce, ttl, count, tagged_objs)
     asa_nonce anonce;
     uint32_t ttl;
     int count;                       // count of tagged objectives
     tagged_objective *tagged_objs[]; // array of tagged objectives
     {}

int  get_flood(anonce, count, tagged_objs)
     asa_nonce anonce;
     int *count;                // count of tagged objectives (zero if no result)  
     tagged_objective *tagged_objs[];  // array of tagged_objectives
                                // The user must free(tagged_objs) asap.
     {}

int  expire_flood(anonce, tagged_obj)
     asa_nonce anonce;
     tagged_objective tagged_obj;
     {}

