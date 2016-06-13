/**
 * Defines and structures for the S7 protocol analyzer
 * Author: Gyorgy Miru
 * Date: 2015.12.11.
 * Version: 0.11
 */

#ifndef ANALYZER_PROTOCOL_S7comm_H
#define ANALYZER_PROTOCOL_S7comm_H

#include <stdio.h>

// Debug print macro
#define S7DEBUG 0
#define DBG(fmt, ...) \
    do { if(S7DEBUG) fprintf(stderr, "%s:%d:%s() " fmt, __FILE__, \
            __LINE__, __func__, __VA_ARGS__);} while (0)


#include <analyzer/protocol/tcp/TCP.h>
#include <analyzer/Analyzer.h>
#include <NetVar.h>
#include <list>

// typedefs
typedef unsigned char u_char;
typedef unsigned short u_int16;
typedef short int16;
typedef unsigned int u_int32;
typedef int int32;

// TODO replace with ntohs
inline u_int16 ubs16(u_int16 us)
{
    return  ((us>>8) & 0xFF) | ((us<<8) & 0xFF00);
}

// TODO replace with ntohl
inline u_int32 ubs32(u_int32 ui)
{
    return ((ui >> 24) & 0x000000FF) |
           ((ui<<8) & 0x00FF0000) |
           ((ui>>8) & 0x0000FF00) |
           ((ui << 24) & 0xFF000000);
}
// TODO replace
inline float bsf(float ui)
{
    float ret=0;
    u_char* src = (u_char*)&ui;
    u_char* dst = (u_char*)&ret;

    //DBG("float dump %f\n", ui);
    dst[0] = src[3];
    DBG("%02x\n", dst[0]);
    dst[1] = src[2];
    DBG("%02x\n", dst[1]);
    dst[2] = src[1];
    DBG("%02x\n", dst[2]);
    dst[3] = src[0];
    DBG("%02x\n", dst[3]);
    
    return ret;
}

// store PLC variable meta data
typedef struct item{
    u_char area;
    u_char item_id;
    u_int16 dbnum;
    u_int16 start;
    u_int16 count;
    u_char size;
    bool is_subitem;
}Item;

// used to match requests and responses
typedef struct request{
    u_int16 pdu_ref;
    int age;
    std::list<Item>* items;
    request()
    {
        items = new std::list<Item>();
    }
    ~request()
    {
        delete items;
    }
    //request(request&& orig)
    //{
    //    pdu_ref = orig.pdu_ref;
    //    age = orig.age;
    //    items = orig.items;
    //    orig.items= NULL;
    //}
    request(const request& orig)
    {
        pdu_ref = orig.pdu_ref;
        age = orig.age;
        items = new std::list<Item>();
        *items = *orig.items;
    }

}Request;

// Structure of the iso-cotp header
typedef struct iso_hdr{
    unsigned char tpkt_version;
    unsigned char tpkt_reserved;
    unsigned short tpkt_length;
    unsigned char cotp_length;
    unsigned char cotp_type;
    //unsigned short rest;
}ISO_HDR;

// iso-cotp connection request header
typedef struct cr_hdr{
    unsigned short dest_ref;
    unsigned short src_ref;
    unsigned char class_options;
}CR_HDR;

// iso-cotp connection info
typedef struct connection_info{
    unsigned short src_tsap;
    unsigned short dst_tsap;
    unsigned char tpdu_len;
}CONN_INFO;

// S7comm pdu header
typedef struct pdu_hdr{
    u_char pid; //0x32
    u_char type; // message type
    u_int16 reserved; //redundancy id always 0
    u_int16 pdu_ref;
    u_int16 param_len;
    u_int16 data_len;
    u_int16 error; //only in ACK msg
} PDU_HDR;


// The S7 Analyzer plugin class
namespace analyzer { namespace Crysys {

class S7comm_Analyzer : public tcp::TCP_ApplicationAnalyzer {
public:
	S7comm_Analyzer(Connection* conn);
    virtual ~S7comm_Analyzer();
	virtual void Done();
    virtual void Init();
	virtual void DeliverStream(int len, const u_char* data, bool orig);

	static analyzer::Analyzer* Instantiate(Connection* conn)
		{
		return new S7comm_Analyzer(conn);
		}

protected:
    // create variable data event from item
	val_list* CreateDataEventVal(Item* item);
    // parse data messages
	const u_char* ParseDataSendEvent(Item* item, const u_char* next_data, bool is_read, int* err);
	int ParseWriteItems(const u_char* data, int offset, int length, const u_char** next_data, int* err);
	int ParseReadItems(list<item>* items, const u_char* data, int offset, int length, int* err);
    // parse S7 requests and responses (non user data message)
	void ParseRequestResponse(val_list* vl, PDU_HDR* main_hdr, const u_char* data, int length, bool orig);
    // parse user data messages
	void ParseUserData(val_list* vl, PDU_HDR* main_hdr, const u_char* data, int length, bool orig);
	// parse the received PDU
    void ParseS7PDU(int length, const u_char* data, bool orig);
    // parse cyclic data TODO (requires S400)
    void ParseCyclicData( const u_char* data, u_char fnmode, u_char fnsub, u_char seqnum); //error, length, dataref
    // list to match requests with responses
    list<Request>* requests;
};
}}
#endif
