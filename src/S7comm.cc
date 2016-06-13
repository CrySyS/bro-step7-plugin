/**
 * This file implements the s7 analyzer plugin
 * Author: Gyorgy Miru
 * Date: 2015.10.27.
 * Version: 0.13
 */

#include <stdlib.h>

#include "S7comm.h"
#include "S7constants.h"
#include "Event.h"
#include "events.bif.h"

using namespace analyzer::Crysys;

S7comm_Analyzer::S7comm_Analyzer(Connection* conn)
: tcp::TCP_ApplicationAnalyzer("S7comm", conn)
	{
    requests = new std::list<Request>();
    //possible place to set up support analyzers
	//nvt_orig = new login::NVT_Analyzer(conn, true);
	//nvt_orig->SetIsNULSensitive(true);
	//AddSupportAnalyzer(nvt_orig);
	}

S7comm_Analyzer::~S7comm_Analyzer()
	{
    requests->clear();
    delete requests;
    // need to clear child analyzers
    }

void S7comm_Analyzer::Init()
    {
    tcp::TCP_ApplicationAnalyzer::Init();
    }

void S7comm_Analyzer::Done()
	{
	tcp::TCP_ApplicationAnalyzer::Done();
    // place to check for partial fin sequence (inproper) 
    //
	//if ( nvt_orig->HasPartialLine() &&
	//     (TCP()->OrigState() == tcp::TCP_ENDPOINT_CLOSED ||
	//      TCP()->OrigPrevState() == tcp::TCP_ENDPOINT_CLOSED) )
		// ### should include the partial text
	//	Weird("partial_ftp_request");
	}

// iso-cotp connection request parsing
static int parse_crcc_variable_class0(CONN_INFO* ci, const unsigned char* variable_part, unsigned int length){
    unsigned int i = 0;
    unsigned char size;
    while (i < length){
        switch(variable_part[i]){
            case SRC_TSAP:
                ci->src_tsap = ubs16(*((unsigned short*)(variable_part + i + 2)));
            case DST_TSAP:
                ci->dst_tsap = ubs16(*((unsigned short*)(variable_part + i + 2)));
            case TPDU_LEN:
                ci->tpdu_len = variable_part[i + 2];
            default:
                i += variable_part[i+1] + 2;
                break;
        }
    }
    return 0;
}

// parses the iso-cotp part of the message
void S7comm_Analyzer::DeliverStream(int length, const u_char* data, bool orig)
	{
	tcp::TCP_ApplicationAnalyzer::DeliverStream(length, data, orig);

	//if ( (orig && ! ftp_request) || (! orig && ! ftp_reply) )
	//	return;

	val_list* vl = new val_list;
	vl->append(BuildConnVal());
	
    ISO_HDR* iso = (ISO_HDR*) data;
    u_int16 tpkt_length = ubs16(iso->tpkt_length);
    CR_HDR* cr;
    CONN_INFO ci;
    int variable_start;

    // get pdu data length
    const unsigned char* PDU_data = data + iso->cotp_length + 5;
    int data_length = length - (iso->cotp_length + 5);

    if (iso->tpkt_version != 3)
        Weird("Unexpected TPKT version");

    if (tpkt_length != length)
    {
        Weird("Ambigous TPKT length");
        DBG("TPKT: %u/%x bro: %d/%x\n", tpkt_length, iso->tpkt_length, length, length);
        DBG("Weird packet DUMP: %0.8x.%0.8x.%0.8x\n", *((u_int32*)data), *((u_int32*)data+1), *((u_int32*)data+2) );
    }
    switch (iso->cotp_type & 0xF0){
        // iso-cotp connection request
        case CR:
            vl->append(new StringVal(18, "Connection Request"));
            vl->append(new Val(iso->cotp_type & 0x0F, TYPE_COUNT));
            cr = (CR_HDR*)(data + sizeof(ISO_HDR));
            if (cr->class_options == 0){
                variable_start = sizeof(ISO_HDR) + sizeof(CR_HDR);
                parse_crcc_variable_class0(&ci, data + variable_start, (iso->cotp_length + 1) - variable_start);
            }
            break;
        // iso-cotp connection confirm
        case CC:
            vl->append(new StringVal(18, "Connection Confirm"));
            vl->append(new Val(iso->cotp_type & 0x0F, TYPE_COUNT));
            cr = (CR_HDR*)(data + sizeof(ISO_HDR));
            if (cr->class_options == 0){
                variable_start = sizeof(ISO_HDR) + sizeof(CR_HDR);
                parse_crcc_variable_class0(&ci, data + variable_start, (iso->cotp_length + 1) - variable_start);
            }
            break;
        // not used by s7
        case DR:
            vl->append(new StringVal(18, "Disconnect Request"));
            vl->append(new Val(0x0, TYPE_COUNT));
            break;
        // not used by s7
        case DC:
            vl->append(new StringVal(18, "Disconnect Confirm"));
            vl->append(new Val(0x0, TYPE_COUNT));
            break;
        // normal S7 message
        case DT:
            vl->append(new StringVal(4, "Data"));
            vl->append(new Val(0x0, TYPE_COUNT));
            break;
        // not used by s7
        case ED:
            vl->append(new StringVal(14, "Expedited Data"));
            vl->append(new Val(0x0, TYPE_COUNT));
            break;
        case AK:
            vl->append(new StringVal(20, "Data Acknowledgement"));
            vl->append(new Val(iso->cotp_type & 0x0F, TYPE_COUNT));
            break;
        // not used by s7
        case EA:
            vl->append(new StringVal(30, "Expedited Data Acknowledgement"));
            vl->append(new Val(0x0, TYPE_COUNT));
            break;
        case RJ:
            vl->append(new StringVal(6, "Reject"));
            vl->append(new Val(iso->cotp_type & 0x0F, TYPE_COUNT));
            break;
        case ERR:
            vl->append(new StringVal(10, "TPDU Error"));
            vl->append(new Val(0x0, TYPE_COUNT));
            break;
        default:
            Weird("Unknown COTP PDU type");            
    }

    // send iso-cotp event
    ConnectionEvent(iso_cotp_packet, vl);
    // than parse the s7 part
    if (data_length>0)
        ParseS7PDU(data_length, PDU_data, orig);

	ForwardStream(length, data, orig);
	}

// used to fill out a val_list based on a data item
val_list*
S7comm_Analyzer::CreateDataEventVal(Item* item)
{
    DBG("Data Item--> area: %u, dbnum: %u, size: %u, start: %u\n", item->area, item->dbnum, item->size, item->start);
    val_list* vl = new val_list();
    vl->append(BuildConnVal());
    vl->append(new Val(item->area, TYPE_COUNT));
    vl->append(new Val(item->dbnum, TYPE_COUNT));
    vl->append(new Val(item->size, TYPE_COUNT));
    vl->append(new Val(item->start, TYPE_COUNT));

    return vl;
}

// parses the data of read/write messages and sends the appropriate events
const u_char*
S7comm_Analyzer::ParseDataSendEvent(Item* item, const u_char* next_data, bool is_read , int* err)
{
    *err=0;
    // different events for signed, unsigned and float data
    EventHandlerPtr fs;
    EventHandlerPtr fu;
    EventHandlerPtr fr;
    if (is_read)
    {
        fs = siemenss7_read_data_signed;
        fu = siemenss7_read_data_unsigned;
        fr = siemenss7_read_data_real;
    }
    else
    {
        fs = siemenss7_write_data_signed;
        fu = siemenss7_write_data_unsigned;
        fr = siemenss7_write_data_real;
    }

    /*Need to get the value for the data Item*/
    // Check if read/write was successful if not return pointer to the next item
    if (!((!is_read && next_data[0] == 0x00) || (is_read && next_data[0] == 0xff)))
    {
        u_int16 size = ubs16(*(u_int16*)(next_data + 2));
        *err = next_data[0];
        return next_data + 4 + size;
    }

    // check if data is subitem
    if (!item->is_subitem)
    {
        // parse the different s7 variable types
        switch(item->size)
        {
            case S7COMM_TRANSPORT_SIZE_BIT:
            case S7COMM_TRANSPORT_SIZE_CHAR:
                for(int i = 0; i < item->count; i++)
                {
                    u_char data = next_data[4 + i];
                    val_list* vl = CreateDataEventVal(item);
                    vl->append(new Val(data, TYPE_COUNT));
                    ConnectionEvent(fu, vl);
                }
                break;
            case S7COMM_TRANSPORT_SIZE_BYTE:
                for(int i = 0; i < item->count; i++)
                {
                    char data = next_data[4 + i];
                    val_list* vl = CreateDataEventVal(item);
                    vl->append(new Val(data, TYPE_INT));
                    ConnectionEvent(fs, vl);

                }
                break;
            case S7COMM_TRANSPORT_SIZE_S5TIME:
            case S7COMM_TRANSPORT_SIZE_DATE:
            case S7COMM_TRANSPORT_SIZE_WORD:
                for(int i = 0; i < item->count; i++)
                {
                    u_int16 data = ubs16(*((u_int16*)(next_data + 4 + 2 * i)));
                    val_list* vl = CreateDataEventVal(item);
                    vl->append(new Val(data, TYPE_COUNT));
                    ConnectionEvent(fu, vl);
                }
                break;
            case S7COMM_TRANSPORT_SIZE_INT:
                for(int i = 0; i < item->count; i++)
                {
                    int16 data = ubs16(*((int16*)(next_data + 4 + 2 * i)));
                    val_list* vl = CreateDataEventVal(item);
                    vl->append(new Val(data, TYPE_INT));
                    ConnectionEvent(fs, vl);
                }
                break;
            case S7COMM_TRANSPORT_SIZE_TIME:
            case S7COMM_TRANSPORT_SIZE_TOD:
            case S7COMM_TRANSPORT_SIZE_DWORD:
                for(int i = 0; i < item->count; i++)
                {
                    u_int32 data = ubs32(*((u_int32*)(next_data + 4 + 4 * i)));
                    val_list* vl = CreateDataEventVal(item);
                    vl->append(new Val(data, TYPE_COUNT));
                    ConnectionEvent(fu, vl);
                }
                break;
            case S7COMM_TRANSPORT_SIZE_DINT:
                for(int i = 0; i < item->count; i++)
                {
                    int32 data = ubs32(*((int32*)(next_data + 4 + 4 * i)));
                    val_list* vl = CreateDataEventVal(item);
                    vl->append(new Val(data, TYPE_INT));
                    ConnectionEvent(fs, vl);
                }
                break;
            case S7COMM_TRANSPORT_SIZE_REAL:
                for(int i = 0; i < item->count; i++)
                {
                    float data = bsf(*((float*)(next_data + 4 + 4 * i)));
                    DBG("Float Value %f dump %08x\n", data, data);
                    val_list* vl = CreateDataEventVal(item);
                    vl->append(new Val(data, TYPE_DOUBLE));
                    ConnectionEvent(fr, vl);
                }
                break;
            case S7COMM_TRANSPORT_SIZE_COUNTER:
            case S7COMM_TRANSPORT_SIZE_TIMER:
            case S7COMM_TRANSPORT_SIZE_IEC_TIMER:
            case S7COMM_TRANSPORT_SIZE_IEC_COUNTER:
            case S7COMM_TRANSPORT_SIZE_HS_COUNTER:
                //TODO figure data length and generate event
            case S7COMM_TRANSPORT_SIZE_DT:
            default:
                *err = ANALYZER_ERROR_UNSUPPORTED_DATA_TYPE;
                u_int16 size = ubs16(*((u_int16*)(next_data + 2)));
                return next_data + 4 + size;
        }
    }
    else
    {
        const u_char *data_ptr = item->item_id == 0 ? next_data + 4: next_data;
        if (data_ptr[0] != 0xff)
        {
            *err = data_ptr[0];
        }

        // we have no type information at this point so we send the data as unsigned
        if (item->count ==1)
        {
            u_char data = data_ptr[1];
            val_list* vl = CreateDataEventVal(item);
            vl->append(new Val(data, TYPE_COUNT));
            ConnectionEvent(fu, vl);
        }
        else if (item->count==2)
        {
            u_int16 data = ubs16(*((u_int16*)(data_ptr + 1)));
            item->size = S7COMM_TRANSPORT_SIZE_WORD;
            val_list* vl = CreateDataEventVal(item);
            vl->append(new Val(data, TYPE_COUNT));
            ConnectionEvent(fu, vl);
        }
        else if (item->count==4)
        {
            u_int32 data = ubs32(*((u_int32*)(data_ptr + 1)));
            item->size = S7COMM_TRANSPORT_SIZE_DWORD;
            val_list* vl = CreateDataEventVal(item);
            vl->append(new Val(data, TYPE_COUNT));
            ConnectionEvent(fu, vl);

        }
        else 
        {
            //u_char data[item->count];
            //memcpy(data, data_ptr + 1, item->count);
            //TODO figure how to send arbitrary data length in event
        }
        return data_ptr + item->count + 1;
    }
    *err = ANALYZER_ERROR_UNEXPECTED_LENGTH;
    return next_data + 4; //TODO check if valid
}

// used to parse write data requests
int
S7comm_Analyzer::ParseWriteItems(const u_char* data, int offset, int length, const u_char** next_data, int* err)
{
    u_char var_spec = data[offset];
    u_char addr_len = data[offset+1];
    Item temp;

    if ((addr_len + 2 + offset) > length || *next_data + 4 > data + length) //TODO check if correct
    {
        Weird("Malformed S7 packet wrong length");
        *err = ANALYZER_ERROR_UNEXPECTED_LENGTH;
        return length;
    }
    u_char pointer_id = data[offset + 2];
    u_char areas;
    // check addressing mode and extract data (request contains it)
    switch (pointer_id)
    {
        case S7COMM_SYNTAXID_S7ANY:
            // normal addressing
            temp.size = data[offset + 3]; //constant
            temp.count = ubs16(*((u_int16*)(data + offset + 4)));
            temp.dbnum = ubs16(*((u_int16*)(data + offset + 6)));
            temp.area = data[offset + 8];
            temp.start = ubs16(*((u_int16*)(data + offset + 10))); // 3 bytes field with 0x00 pad (padding start needs to be checked!)
            temp.item_id = 0;
            temp.is_subitem = false;
            
            *next_data = ParseDataSendEvent(&temp, *next_data, false, err);

            break;
        case S7COMM_SYNTAXID_DBREAD:
            areas = data[offset + 3];
            if (2 + areas * 5 > addr_len)
            {
                // Error malformed packet
                Weird("Malformed S7 packet wrong length");
                *err = ANALYZER_ERROR_UNEXPECTED_LENGTH;
                return length;
            }
            for (int i = 0; i < areas; i++)
            {
                temp.size =  S7COMM_TRANSPORT_SIZE_BYTE;
                temp.count = data[offset + (i * 5) + 4];
                temp.dbnum = ubs16(*((u_int16*)(data + offset + (i * 5) + 5)));
                temp.area = S7COMM_AREA_DB; //area db 
                temp.start = ubs16(*((u_int16*)(data + offset + (i * 5) + 7)));
                temp.item_id = i;
                temp.is_subitem = true;

                *next_data = ParseDataSendEvent(&temp, *next_data, false, err);
            }
            //  special    
            break;
        case S7COMM_SYNTAXID_1200SYM:
            //TODO symbolic addressing used by s1200 series 
            //note must be handled to set data pointer
            *err = ANALYZER_ERROR_UNSOPPORTED_ADDRESSING;
            return length;
        default:
            Weird("Unsupported Variable Addressing");
            *err = ANALYZER_ERROR_UNSOPPORTED_ADDRESSING;
            return length;
    }
    
    return offset + addr_len + 2;
}

// extract variable data from read request (response only contains the data)
int
S7comm_Analyzer::ParseReadItems(std::list<Item>* items, const u_char* data, int offset, int length, int* err)
{
    //parse read request
    u_char var_spec  = data[offset];
    u_char addr_len = data[offset+1];
    Item temp;
    /* Classic S7:  type = 0x12, len=10, syntax-id=0x10 for ANY-Pointer
     * TIA S7-1200: type = 0x12, len=14, syntax-id=0xb2 (symbolic addressing??)
     * Drive-ES Starter with routing: type = 0x12, len=10, syntax-id=0xa2 for ANY-Pointer
     */
    if ((addr_len + 2 + offset) > length)
    {
        // Error malformed packet
        Weird("Malformed S7 packet wrong length");
        *err = ANALYZER_ERROR_UNEXPECTED_LENGTH;
        return length;
    }
    u_char pointer_id = data[offset+2];
    u_char areas;
    switch (pointer_id)
    {
        case S7COMM_SYNTAXID_S7ANY:
            // normal addressing
            temp.size = data[offset +3]; //constant
            temp.count = ubs16(*((u_int16*)(data + offset+4)));
            temp.dbnum = ubs16(*((u_int16*)(data + offset+6)));
            temp.area = data[offset + 8];
            temp.start = ubs16(*((u_int16*)(data + offset+10))); // 3 bytes field with 0x00 pad (padding start needs to be checked!)
            temp.item_id = 0;
            temp.is_subitem = false;

            items->push_back(temp);
            DBG("Read item--> size: %u, count: %u, dbnum: %u, area: %x, start: %u\n", temp.size, temp.count, temp.dbnum, temp.area, temp.start);
            break;
        case S7COMM_SYNTAXID_DBREAD:
            {
            areas = data[offset + 3];
            if (2 + areas * 5 > addr_len)
            {
                // Error malformed packet
                DBG("expected length: %u, real: %u\n", addr_len, 2 + areas*5);
                Weird("Malformed S7 packet wrong length");
                *err = ANALYZER_ERROR_UNEXPECTED_LENGTH;
                return length;
            }
            for (int i = 0; i < areas; i++)
            {
                temp.size =  S7COMM_TRANSPORT_SIZE_BYTE;
                temp.count = data[offset + (i * 5) + 4];
                temp.dbnum = ubs16(*((u_int16*)(data + offset + (i*5) + 5)));
                temp.area = S7COMM_AREA_DB; //area db 
                temp.start = ubs16(*((u_int16*)(data + offset+(i*5)+7)));
                temp.item_id = i;
                temp.is_subitem = true;
                
                items->push_back(temp);
                DBG("Read item--> size: %u, count: %u, dbnum: %u, area: %x, start: %u\n", temp.size, temp.count, temp.dbnum, temp.area, temp.start);
            }
            //  special    
            break;
            }
        case S7COMM_SYNTAXID_1200SYM:
            //TODO reverse s1200 symbolic addressing
            *err = ANALYZER_ERROR_UNSOPPORTED_ADDRESSING;
            return length;
        default:
            Weird("Unsupported Variable Addressing");
            *err = ANALYZER_ERROR_UNSOPPORTED_ADDRESSING;
            return length;
    }
 
    return offset + addr_len + 2;
        
}

// parse the requests and responses (it contains the data for read requests)
void
S7comm_Analyzer::ParseRequestResponse(val_list* vl, PDU_HDR* main_hdr, const u_char* data, int length, bool orig)
{
    int offset = 0;
    u_char function = data[offset];
    offset++;
    vl->append(new Val(function, TYPE_COUNT));
    int err = 0;
    int len;

    if (main_hdr->type == S7COMM_ROSCTR_JOB) 
    {
        switch (function)
        {
            // read request
            case S7COMM_SERV_READVAR:
                {
                u_char item_count = data[offset];  
                offset += 1;
                
                DBG("ReadVar request cnt: %u\n", item_count);
                Request temp;
                temp.pdu_ref = main_hdr->pdu_ref;
                temp.age = 0;
                int offset_old;
                /* parse item data */
                for (int i = 0; i < item_count; i++)
                {
                    offset_old = offset;
                    offset = ParseReadItems(temp.items, data, offset, length, &err);
                    /* if length is not a multiple of 2 and this is not the last item, then add a fill-byte */
                    len = offset - offset_old;
                    if ((len % 2) && (i < item_count)) 
                    {
                        offset += 1;
                    }
                    if (offset >= length)
                    {
                        break;
                    }
                }
                requests->push_back(temp);

                break;
                }
            // write requests
            case S7COMM_SERV_WRITEVAR:
                {
                u_char item_count = data[offset];
                const u_char* real_data = data + main_hdr->param_len;
                offset += 1;
                
                int offset_old;
                DBG("Writevar request cnt: %u\n", item_count);
                /* parse item data */
                for (int i = 0; i < item_count; i++)
                {
                    offset_old = offset;
                    offset = ParseWriteItems(data, offset, length, &real_data, &err);
                    /* if length is not a multiple of 2 and this is not the last item, then add a fill-byte */
                    len = offset - offset_old;
                    if ((len % 2) && (i < item_count)) 
                    {
                        offset += 1;
                    }
                    if (offset >= length)
                    {
                        break;
                    }
                }

                break;
                }
            // these functions are no longer parsed, they are logged tho
            case S7COMM_SERV_SETUPCOMM:
            /* Special functions */
            //parsing the affected block could useful TODO
            case S7COMM_FUNCREQUESTDOWNLOAD:
            case S7COMM_FUNCDOWNLOADBLOCK:
            case S7COMM_FUNCDOWNLOADENDED:
            case S7COMM_FUNCSTARTUPLOAD:
            case S7COMM_FUNCUPLOAD:
            case S7COMM_FUNCENDUPLOAD:
            case S7COMM_FUNC_PLC_CONTROL:
            case S7COMM_FUNC_PLC_STOP:
            default:
                  break;
        }
    } //parse replies
    else if (main_hdr->type == S7COMM_ROSCTR_ACK_DATA) 
    {
        switch (function)
        {
            // extract the read data and match it with the request
            case S7COMM_SERV_READVAR:
                {
                u_char item_count = data[offset];  
                offset += 1;
                const u_char* next_data = &data[offset];
                
                /* handle read ack */
                for (std::list<Request>::iterator it  = requests->begin(); it != requests->end(); )
                {
                    DBG("Request list--> pdu ref: %u count: %lu age: %d\n", it->pdu_ref, it->items->size(), it->age);
                    if (it->pdu_ref == main_hdr->pdu_ref)
                    {
                        // read variable data
                        if (item_count != it->items->size())
                        {
                            err = ANALYZER_ERROR_UNEXPECTED_ITEM_COUNT;
                        }
                        for (std::list<Item>::iterator il = it->items->begin(); il != it->items->end(); il++)
                        {
                            next_data = ParseDataSendEvent(&(*il), next_data, true, &err);
                        }
                        it = requests->erase(it);
                    }
                    else if (it->age >= S7COMM_MAX_AGE)
                    {
                        // drop the request
                        it = requests->erase(it);
                    }
                    else
                    {
                        it->age++;
                        it++;
                    }
                }
                
                break;
                }
            case S7COMM_SERV_WRITEVAR:
                
                break;
            case S7COMM_SERV_SETUPCOMM:
                break;
            default:
                
                break;
        }
        
    }
    // raise the s7 message type event
    vl->append(new Val(err, TYPE_COUNT));
    ConnectionEvent(siemenss7_packet, vl);
}

// s7-400 plcs can periodically push data, this needs to be reversed TODO
void
S7comm_Analyzer::ParseCyclicData( const u_char* data, u_char fnmode, u_char fnsub, u_char seqnum) //error, length, dataref
{
    return;
}

// parse user data messages
void
S7comm_Analyzer::ParseUserData(val_list* vl, PDU_HDR* main_hdr, const u_char* data, int length, bool orig)
{
    // SZL READS + CYCLIC updates
    u_int32 offset = 0;
    u_char fnmode;
    u_char fntype;
    u_char fnsub;
    u_char param_length;
    u_char seqnum;
    u_char datauref = 0;
    u_int16 error = 0;
    if (length < 4)
    {
        Weird("Malformed UserData packet cannot parse it!");
        return;
    }
    offset += 3; //skipping 3 byte constant parameter head (0x00010C)
    param_length = data[offset++];
    if (length < 4 + param_length || param_length < 4)
    {
        Weird("Malformed UserData parameter length cannot parse it!");
        return;
    }
    offset++; //skipping reqresp field
    fnmode = (data[offset] & 0xf0) >> 4;
    fntype = data[offset++] & 0x0f;
    fnsub = data[offset++];

    if (param_length == 8)
    {
        error = ubs16(*(u_int16*)(data + 10));
    }

    if (fnmode == S7COMM_UD_TYPE_REQ && !orig)
    {
        Weird("UserData request coming from slave!");
    }
    else if ( (fnmode == S7COMM_UD_TYPE_PUSH || fnmode == S7COMM_UD_TYPE_RES) && orig)
    {
        Weird("UserData response coming from master!");
    }
    // send user data request type and subtype
    vl->append(new Val(fnmode, TYPE_COUNT));
    vl->append(new Val(fntype, TYPE_COUNT));
    vl->append(new Val(fnsub, TYPE_COUNT));
    vl->append(new Val(error, TYPE_COUNT));
    ConnectionEvent(siemenss7_ud_packet, vl);
    
    // Parse Cyclic Data
    if ( fntype == S7COMM_UD_FUNCGROUP_CYCLIC)
    {
        seqnum = data[offset++];
        if (param_length > 4)
        {
            datauref = data[offset];
        }
        ParseCyclicData(data, fnmode, fnsub, seqnum);
    }
    // parsing szl requests and authentication requests could be useful TODO

    return;
}

// parses the S7 header than calls the apprpriate subfunction
void
S7comm_Analyzer::ParseS7PDU(int length, const u_char* data, bool orig)
{
    PDU_HDR main_hdr;
    memcpy(&main_hdr, data, sizeof(PDU_HDR));
    main_hdr.param_len = ubs16(main_hdr.param_len);
    main_hdr.data_len = ubs16(main_hdr.data_len);
    main_hdr.error = ubs16(main_hdr.error);

    val_list* vl = new val_list;
    vl->append(BuildConnVal());

    if (main_hdr.pid != 0x32)
    {
        Weird("Unexpected Protocol ID, non s7 data");
        return;
    }
    if(length < S7COMM_MIN_TELEGRAM_LENGTH)
    {
        Weird("Data too short for s7 packet");
        return;
    }
    if (main_hdr.type  < 0x01 || main_hdr.type > 0x07)
    {
        Weird("Unrecognized s7 message type");
        return;
    }
    
    vl->append(new Val(main_hdr.type, TYPE_COUNT));
    switch (main_hdr.type)
    {
        // S7 requests
        case S7COMM_ROSCTR_JOB:
            if(orig)
            {           
                ParseRequestResponse(vl, &main_hdr, data+10, length-10, orig);
            }
            else
            {
                // this might happen legitemately during block upload
                Weird("Job request coming from the slave");
                return;
            }
            break;
        // S7 response
        case S7COMM_ROSCTR_ACK_DATA:
            if(!orig && !main_hdr.error)
            {
                ParseRequestResponse(vl, &main_hdr, data+12, length-12, orig);
            }
            else
            {
                if(orig)
                {
                    Weird("Job Response coming from master!");
                    return;
                }
                //TODO raise error event!

            }
            break;
        // 
        case S7COMM_ROSCTR_USERDATA:
            ParseUserData(vl, &main_hdr, data+10, length-10, orig);
            break;
        case S7COMM_ROSCTR_ACK:
            //TODO when does this even come?
            break;
        default:
            Weird("Unknown s7 message type");
            return;
    }
}

